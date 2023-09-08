package action

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/gopasspw/gopass/internal/action/exit"
	"github.com/gopasspw/gopass/internal/hook"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/urfave/cli/v2"
)

// Exec a command with a secret file.
func (s *Action) Exec(c *cli.Context) error {
	name := c.Args().Get(0)
	command := c.Args().Get(1)

	ctx := ctxutil.WithGlobalFlags(c)

	if err := s.exec(ctx, c, name, command); err != nil {
		return exit.Error(exit.Decrypt, err, "%s", err)
	}

	return hook.InvokeRoot(ctx, "exec.post-hook", name, s.Store)
}

// exec displays the given secret/key.
func (s *Action) exec(ctx context.Context, c *cli.Context, name, command string) error {
	if name == "" || command == "" {
		return exit.Error(exit.Usage, nil, "Usage: %s exec name cmd [filename]", s.Name)
	}

	if !s.Store.Exists(ctx, name) || s.Store.IsDir(ctx, name) {
		return exit.Error(exit.NotFound, nil, "%s is not a secret", name)
	}

	sec, err := s.Store.Get(ctx, name)
	if err != nil {
		return exit.Error(exit.Decrypt, err, "failed to read secret: %s", err)
	}

	// TODO: make a fifo!
	filename := c.String("filename")
	if filename != "" {
		_, err = os.Stat(filename)
		if err == nil || err != nil && !os.IsNotExist(err) {
			return exit.Error(exit.Unsupported, nil, "could not stat %s: %v", filename, err)
		}
		err := os.WriteFile(filename, sec.Bytes(), 0600)
		if err != nil {
			return exit.Error(exit.IO, nil, "failed to write: %v", err)
		}
		defer os.RemoveAll(filename)
	} else {
		dir, err := os.MkdirTemp("", ".gopass")
		if err != nil {
			return exit.Error(exit.IO, nil, "failed to create temporary directory")
		}
		defer os.RemoveAll(dir)
		f, err := os.CreateTemp(dir, "*")
		if err != nil {
			return exit.Error(exit.IO, nil, "failed to create temporary file")
		}
		_, err = f.Write(sec.Bytes())
		if err != nil {
			return exit.Error(exit.IO, nil, "failed to write temporary file")
		}
		f.Close()
		filename = f.Name()
	}

	cmd := exec.Command("/bin/sh", "-c", strings.ReplaceAll(command, "{file}", filename))
	cmd.Env = os.Environ()

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
