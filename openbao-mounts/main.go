package main

import (
	"fmt"
	"sync"

	"github.com/openbao/openbao/api/v2"
)

func main() {
	addr := "http://localhost:8200"
	token := "s.9ilUgeB0BSUmeBC4ibili6GP"
	mountType := "ssh"
	count := 360000
	procs := 2

	client, err := api.NewClient(&api.Config{
		Address: addr,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create client: %v", err))
	}

	client.SetToken(token)

	var wg sync.WaitGroup

	for proc := 0; proc < procs; proc++ {
		wg.Add(1)
		go func(us int) {
			for i := us * (count / procs); i < (us+1)*(count/procs); i++ {
				if err := client.Sys().Mount(fmt.Sprintf("%v-%v", mountType, i), &api.MountInput{
					Type: mountType,
				}); err != nil {
					// panic(fmt.Sprintf("failed to mount %v instance: %v", mountType, err))
				}
				/*if _, err := client.Logical().Write(fmt.Sprintf("%v-%v/config/ca", mountType, i), map[string]interface{}{
					"generate_signing_key": true,
					"key_type":             "ssh-ed25519",
				}); err != nil {
					// fmt.Fprintf(os.Stderr, "failed to mount %v instance: %v", mountType, err)
				}*/
			}
			wg.Done()
		}(proc)
	}

	wg.Wait()
}
