// Copyright © 2017 Lee Briggs <lee@leebriggs.co.uk>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
	"io"
	"os"

	v "github.com/jaxxstorm/hookpick/vault"

	//"github.com/acidlemon/go-dumper"
	"sync"

	"github.com/jaxxstorm/hookpick/config"
	"github.com/jaxxstorm/hookpick/gpg"
)

var pgpkeypath string
var pgpkey string
var otp string

// generateRootCmd represents the generate-root command
var generateRootCmd = &cobra.Command{
	Use:   "generate-root",
	Short: "Runs generate-root operations against Vault servers",
	Long: `Runs generate-root operations against all Vault servers
or specified Vault servers in the configuration file`,
}

var generateRootInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Starts the generate-root operation on specified Vault server",
	Long: `Initialises a generate-root against specified Vault servers
and returns the client nonce needed for other generate-root operators`,
	Run: func(cmd *cobra.Command, args []string) {

		if pgpkeypath != "" {
			log.Info("PGP key provided")

		} else {

		}

		if otp == "" {
			log.Info("No OTP key provided")
		}

		allDCs := GetDatacenters()
		configHelper := NewConfigHelper(GetSpecificDatacenter, GetCaPath, GetProtocol, GetGpgKey)

		wg := sync.WaitGroup{}
		// loop through datacenters
		for _, dc := range allDCs {
			wg.Add(1)
			go ProcessGenerateRoot(&wg, dc, configHelper, v.NewVaultHelper, HostGenerateRootInit)
		}
		wg.Wait()
	},
}

var generateRootSubmitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submits your key to the generate-root command",
	Long: `Submits your unseal key to the generate-root process
and progresses the generate-root`,
	Run: func(cmd *cobra.Command, args []string) {
		allDCs := GetDatacenters()
		configHelper := NewConfigHelper(GetSpecificDatacenter, GetCaPath, GetProtocol, GetGpgKey)
		gpgHelper := gpg.NewGPGHelper(gpg.Decrypt)

		wg := sync.WaitGroup{}

		for _, dc := range allDCs {
			wg.Add(1)
			go ProcessGenerateRootSubmit(&wg, dc, configHelper, v.NewVaultHelper, gpgHelper, GetVaultKeys, HostGenerateRootSubmit)
		}
		wg.Wait()
	},
}

var generateRootStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Retrieves the current status of a generate-root",
	Long: `Retrieves the current status of a generate-root process
from all the specified Vault servers`,
	Run: func(cmd *cobra.Command, args []string) {

		allDCs := GetDatacenters()
		configHelper := NewConfigHelper(GetSpecificDatacenter, GetCaPath, GetProtocol, GetGpgKey)

		wg := sync.WaitGroup{}

		for _, dc := range allDCs {
			wg.Add(1)
			log.WithFields(log.Fields{
				"datacenter": dc.Name,
			}).Debugln("Starting to process generate-root")
			go ProcessGenerateRoot(&wg, dc, configHelper, v.NewVaultHelper, HostGenerateRootStatus)
		}
		wg.Wait()
	},
}

var generateRootCancelCmd = &cobra.Command{
	Use:   "cancel",
	Short: "Cancels the current generate-root",
	Long: `Cancels the current generate-root process
from all the specified Vault servers`,
	Run: func(cmd *cobra.Command, args []string) {

		allDCs := GetDatacenters()
		configHelper := NewConfigHelper(GetSpecificDatacenter, GetCaPath, GetProtocol, GetGpgKey)

		wg := sync.WaitGroup{}

		for _, dc := range allDCs {
			wg.Add(1)
			log.WithFields(log.Fields{
				"datacenter": dc.Name,
			}).Debugln("Starting to process generate-root")
			go ProcessGenerateRoot(&wg, dc, configHelper, v.NewVaultHelper, HostGenerateRootCancel)
		}
		wg.Wait()
	},
}

func ProcessGenerateRoot(wg *sync.WaitGroup,
	dc config.Datacenter,
	configHelper *ConfigHelper,
	vhGetter v.VaultHelperGetter,
	hostGenerateRootInit HostImpl) {
	defer wg.Done()

	specificDC := configHelper.GetDC()
	caPath := configHelper.GetCAPath()
	protocol := configHelper.GetURLScheme()

	log.WithFields(log.Fields{
		"datacenter": dc.Name,
		"dc":         specificDC,
	}).Debugln("Processing generate-root for")

	if specificDC == dc.Name || specificDC == "" {

		hwg := sync.WaitGroup{}
		for _, host := range dc.Hosts {
			hwg.Add(1)
			log.WithFields(log.Fields{
				"host": host.Name,
			}).Debugln("Starting to process generate-root")
			vaultHelper := vhGetter(host.Name, caPath, protocol, host.Port, v.Status)
			go hostGenerateRootInit(&hwg, vaultHelper)
		}
		hwg.Wait()
	}
}

func ProcessGenerateRootSubmit(wg *sync.WaitGroup,
	dc config.Datacenter,
	configHelper *ConfigHelper,
	vhGetter v.VaultHelperGetter,
	gpgHelper *gpg.GPGHelper,
	vaultKeysGetter VaultKeyGetter,
	submitHostGenerateRoot HostSubmitImpl) {
	defer wg.Done()

	specificDC := configHelper.GetDC()
	caPath := configHelper.GetCAPath()
	protocol := configHelper.GetURLScheme()

	log.WithFields(log.Fields{
		"datacenter": dc.Name,
		"dc":         specificDC,
	}).Debugln("Processing generate-root for")

	if specificDC == dc.Name || specificDC == "" {

		vaultKeys := vaultKeysGetter(dc, configHelper.GetGPGKey, gpgHelper.Decrypt)

		hwg := sync.WaitGroup{}
		for _, host := range dc.Hosts {
			hwg.Add(1)
			log.WithFields(log.Fields{
				"host": host.Name,
			}).Debugln("Starting to process generate-root")

			vaultHelper := vhGetter(host.Name, caPath, protocol, host.Port, v.Status)
			go submitHostGenerateRoot(&hwg, vaultHelper, vaultKeys)
		}
		hwg.Wait()
	}
}

func tryLoadKey(pgpkeyfilepath string) (keyout string, err error) {
	keyfile, err := os.Open(pgpkeyfilepath)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = openpgp.ReadArmoredKeyRing(keyfile)
	if err != nil {
		return
	}

	var buf bytes.Buffer
	io.Copy(&buf, keyfile)
	keyout = buf.String()

	return keyout, nil
}

func HostGenerateRootInit(wg *sync.WaitGroup, vaultHelper *v.VaultHelper) {
	defer wg.Done()
	client, err := vaultHelper.GetVaultClient()

	if err != nil {
		log.WithFields(log.Fields{
			"host": vaultHelper.HostName,
			"port": vaultHelper.Port,
		}).Errorln(err)
	}

	log.WithFields(log.Fields{
		"host": vaultHelper.HostName,
	}).Debugln("Starting generate-root init")

	// check init status
	sealed, init := vaultHelper.GetStatus(client)

	if init == true && sealed == false {
		// get the current leader to operate on
		result, _ := client.Sys().Leader()
		// if we are the leader start the generate-root
		if result.IsSelf == true {
			//load the key
			pgpkey, err = tryLoadKey(pgpkeypath)
			if err != nil {
				log.Errorln("generate-root key loading error ", err)
			}
			generateRootResult, err := client.Sys().GenerateRootInit("", pgpkey)
			if err != nil {
				log.Errorln("generate-root init error ", err)
			}
			if generateRootResult.Started {
				log.WithFields(log.Fields{
					"host":       vaultHelper.HostName,
					"pgpkeypath": generateRootResult.PGPFingerprint,
					"nonce":      generateRootResult.Nonce,
				}).Infoln("Generate Root Started. Please supply your keys.")
			}
		}
	}
}

func HostGenerateRootStatus(wg *sync.WaitGroup, vaultHelper *v.VaultHelper) {
	defer wg.Done()
	client, err := vaultHelper.GetVaultClient()

	if err != nil {
		log.WithFields(log.Fields{"host": vaultHelper.HostName, "port": vaultHelper.Port}).Error(err)
	}

	log.WithFields(log.Fields{
		"host": vaultHelper.HostName,
	}).Debugln("Starting generate-root status")

	// check init status
	sealed, init := vaultHelper.GetStatus(client)

	if init == true && sealed == false {
		result, _ := client.Sys().Leader()
		// if we are the leader start the generate-root
		if result.IsSelf == true {
			generateRootStatus, err := client.Sys().GenerateRootStatus()

			if err != nil {
				log.WithFields(log.Fields{
					"host":  vaultHelper.HostName,
					"port":  vaultHelper.Port,
					"error": err,
				}).Errorln("Error getting generate-root status")
			}
			if generateRootStatus.Started {
				log.WithFields(log.Fields{
					"host":     vaultHelper.HostName,
					"nonce":    generateRootStatus.Nonce,
					"progress": generateRootStatus.Progress,
					"required": generateRootStatus.Required,
				}).Infoln("Generate root has been started")
			} else {
				log.WithFields(log.Fields{
					"host": vaultHelper.HostName,
				}).Infoln("Generate root not started")
			}
		}
	}
}

func HostGenerateRootCancel(wg *sync.WaitGroup, vaultHelper *v.VaultHelper) {
	defer wg.Done()
	client, err := vaultHelper.GetVaultClient()

	if err != nil {
		log.WithFields(log.Fields{"host": vaultHelper.HostName, "port": vaultHelper.Port}).Error(err)
	}

	log.WithFields(log.Fields{
		"host": vaultHelper.HostName,
	}).Debugln("Starting generate-root status")

	// check init status
	sealed, init := vaultHelper.GetStatus(client)

	if init == true && sealed == false {
		result, _ := client.Sys().Leader()
		// if we are the leader start the generate-root
		if result.IsSelf == true {
			err := client.Sys().GenerateRootCancel()

			if err != nil {
				log.WithFields(log.Fields{
					"host":  vaultHelper.HostName,
					"port":  vaultHelper.Port,
					"error": err,
				}).Errorln("Error executing generate-root cancel")
			}
			log.WithFields(log.Fields{"host": vaultHelper.HostName}).Infoln("Generate root cancelled")
		}
	}
}

func HostGenerateRootSubmit(wg *sync.WaitGroup, vaultHelper *v.VaultHelper, vaultKeys []string) bool {
	defer wg.Done()
	client, err := vaultHelper.GetVaultClient()
	if err != nil {
		log.WithFields(log.Fields{
			"host":  vaultHelper.HostName,
			"port":  vaultHelper.Port,
			"error": err,
		}).Errorln("Error getting vault client")
	}

	log.WithFields(log.Fields{
		"host": vaultHelper.HostName,
	}).Debugln("Starting generateRoot submit")

	// check init status
	sealed, init := vaultHelper.GetStatus(client)

	if init == true && sealed == false {
		result, _ := client.Sys().Leader()
		// if we are the leader start the generateRoot
		if result.IsSelf == true {
			generateRootStatus, err := client.Sys().GenerateRootStatus()
			if err != nil {
				log.WithFields(log.Fields{
					"host":  vaultHelper.HostName,
					"port":  vaultHelper.Port,
					"error": err,
				}).Errorln("Error getting generate-root status")

				return false
			}

			if generateRootStatus.Started {
				for _, vaultKey := range vaultKeys {
					generateRootUpdate, err := client.Sys().GenerateRootUpdate(vaultKey, generateRootStatus.Nonce)
					if err != nil {
						log.WithFields(log.Fields{
							"host":  vaultHelper.HostName,
							"port":  vaultHelper.Port,
							"error": err,
						}).Errorln("Error updating generate-root")

						continue
					}

					if generateRootUpdate.Complete {

						log.WithFields(log.Fields{
							"host": vaultHelper.HostName,
						}).Info("GenerateRoot Complete")

						log.WithFields(log.Fields{"EncodedRootToken": generateRootUpdate.EncodedRootToken}).Infoln("Encoded Root Token Generated")
						log.WithFields(log.Fields{"EncodedToken": generateRootUpdate.EncodedToken}).Infoln("Encoded Token Generated")

						break
					} else {
						newGenerateRootStatus, err := client.Sys().GenerateRootStatus()
						if err != nil {
							log.WithFields(log.Fields{
								"host":  vaultHelper.HostName,
								"port":  vaultHelper.Port,
								"error": err,
							}).Errorln("Error getting generate-root status")
						}
						log.WithFields(log.Fields{
							"host":     vaultHelper.HostName,
							"nonce":    newGenerateRootStatus.Nonce,
							"progress": newGenerateRootStatus.Progress,
							"required": newGenerateRootStatus.Required,
						}).Infoln("Key submitted")
					}
				}
			} else {
				log.WithFields(log.Fields{
					"host": vaultHelper.HostName,
				}).Infoln("generate-root not started")
			}
		}
	}
	return true
}

func init() {
	RootCmd.AddCommand(generateRootCmd)
	generateRootCmd.AddCommand(generateRootInitCmd)
	generateRootCmd.AddCommand(generateRootSubmitCmd)
	generateRootCmd.AddCommand(generateRootStatusCmd)
	generateRootCmd.AddCommand(generateRootCancelCmd)

	generateRootInitCmd.Flags().StringVarP(&pgpkeypath, "pgpkey", "p", "", "path to the pgp key to encrypt the token with")

}
