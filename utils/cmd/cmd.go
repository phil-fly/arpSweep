package cmd

import (
	"bytes"
	"log"
	"os/exec"
	"syscall"
)

func RunInWindows(cmdstr string) (string,error){

	cmd := exec.Command("cmd","/c",  cmdstr)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	if err != nil {
		log.Println(err.Error(), stderr.String())
		return "", err
	} else {
		return out.String(), err
	}
}
