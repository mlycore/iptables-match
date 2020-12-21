/*
KubeStar™ is a cloud native CaaS platform.
Copyright (C) 2019  Xuyun Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"fmt"
	"github.com/mlycore/go-iptables/iptables"
	"github.com/mlycore/iptables-match/service"
	"strings"
)

type ChainMeta struct {
	ChainName string
	Rules     []Rule
	Stats     []iptables.Stat
}

func (cm ChainMeta) Name() string {
	return cm.ChainName
}

func (cm ChainMeta) Print() {
	for _, r := range cm.Rules {
		r.Print()
	}
}

func (cm ChainMeta) Handle() service.Services {
	existedService := map[string]bool{}
	servicesMap := map[string]service.Service{}
	targetMap := map[string][]iptables.Stat{}
	services := []service.Service{}
	if cm.ChainName == ChainKubeNodePorts {
		for _, s := range cm.Stats {
			// Options:/* archery/archery:web-http */ tcp dpt:30103
			opts := strings.Split(s.Options, " ")
			namespace := strings.Split(opts[1], "/")[0]
			name := strings.Split(strings.Split(opts[1], "/")[1], ":")[0]
			nodeport := strings.Split(opts[len(opts)-1], ":")[1]
			this := service.Service{
				Name:      name,
				Namespace: namespace,
				Ports:     []service.Port{},
				ClusterIP: "",
				//Endpoints: nil,
			}
			this.Ports = append(this.Ports, service.Port{
				NodePort: nodeport,
			})
			if !existedService[fmt.Sprintf("%s/%s", this.Namespace, this.Name)] {
				//services = append(services, service)
				key := fmt.Sprintf("%s/%s", this.Namespace, this.Name)
				servicesMap[key] = this
				existedService[key] = true
			}
		}
	}

	if cm.ChainName == ChainKubeServices {
		for _, s := range cm.Stats {
			// {Packets:0 Bytes:0 Target:KUBE-SVC-ERIFXISQEP7F7OF4 Protocol:tcp Opt:-- Input:* Output:* Source:0.0.0.0/0 Destination:172.20.0.10/32 Options:/* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53}
			opts := strings.Split(s.Options, " ")
			namespace := strings.Split(opts[1], "/")[0]
			//log.Infof("opts: %+v", opts)
			if strings.Contains(s.Options, "NOTE") {
				continue
			}
			name := strings.Split(strings.Split(opts[1], "/")[1], ":")[0]
			port := strings.Split(opts[len(opts)-1], ":")[1]
			clusterIP := s.Destination.IP.String()

			this := service.Service{
				Name:      name,
				Namespace: namespace,
				ClusterIP: clusterIP,
				Ports:     []service.Port{},
			}
			this.Ports = append(this.Ports, service.Port{
				Port: port,
			})
			services = append(services, this)
		}
	}

	if strings.Contains(cm.ChainName, "KUBE-SVC-") {
		for _, s := range cm.Stats {
			targetMap[s.Target] = append(targetMap[s.Target], s)
		}
	}

	svcs := service.Services{Items: []service.Service{}}
	for _, svc := range services {
		svcs.Items = append(svcs.Items, svc)
	}

	return svcs
}

type KubeServices struct {
	ChainMeta
}

type KubeExternalServices struct {
	ChainMeta
}

type KubeNodePorts struct {
	ChainMeta
}

type KubePostRouting struct {
	ChainMeta
}

type KubeMarkMasq struct {
	ChainMeta
}

type KubeMarkDrop struct {
	ChainMeta
}

type KubeForward struct {
	ChainMeta
}
