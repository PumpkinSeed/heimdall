package unseal

import (
	"io"
	"net"
	"sync"

	"github.com/PumpkinSeed/heimdall/internal/api/socket"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var Cmd = &cli.Command{
	Name:   "unseal",
	Action: action,
}

func action(ctx *cli.Context) error {
	c, err := net.Dial("unix", socket.Path)
	if err != nil {
		return err
	}
	defer c.Close()

	key := ctx.Args().First()
	log.Debugf("sending key: %s", key)

	if _, err := c.Write([]byte(key)); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go readResult(c, &wg)
	wg.Wait()

	return nil
}

func readResult(r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil {
		log.Fatalf("Result read error: %v", err)
		return
	}
	log.Infof("Client got: %s", string(buf[0:n]))
}
