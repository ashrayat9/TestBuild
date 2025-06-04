package proxy

import "net"

type AppListner struct {
	c chan net.Conn
}

func (l *AppListner) Accept() (net.Conn, error) {
	c := <-l.c
	return c, nil
}

func (l *AppListner) Addr() net.Addr {
	return nil
}

func (l *AppListner) Close() error {
	return nil
}
