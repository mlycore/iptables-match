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

package nat

import (
	"fmt"
	"github.com/mlycore/go-iptables/iptables"
	"github.com/mlycore/iptables-match/service"
	"github.com/mlycore/log"
	"strings"
)

const (
	TableNat = "nat"

	ChainKubeServices         = "KUBE-SERVICES"
	ChainKubeExternalServices = "KUBE-EXTERNAL-SERVICES"
	ChainKubeNodePorts        = "KUBE-NODEPORTS"
	ChainKubePostRouting      = "KUBE-POSTROUTING"
	ChainKubeMarkMasq         = "KUBE-MARK-MASQ"
	ChainKubeMarkDrop         = "KUBE-MARK-DROP"
	ChainKubeForward          = "KUBE-FORWARD"
	ChainKubeSepPrefix        = "KUBE-SEP-"
	ChainKubeSvcPrefix        = "KUBE-SVC-"
	ChainDNAT                 = "DNAT"
)

func Handle(table *iptables.IPTables) {
	//existedService := map[string]bool{}
	servicesMap := map[string]service.Service{}
	endpointsMap := map[string]string{}
	targetMap := map[string]map[string]iptables.Stat{}
	list := &service.Services{Items: []service.Service{}}

	chains, err := table.ListChains(TableNat)
	if err != nil {
		log.Errorf("list chains error: %s", err)
		return
	}

	for _, c := range chains {
		stats, err := table.Stats(TableNat, c)
		if err != nil {
			log.Warnf("get stats error: %s", err)
			continue
		}
		if c == ChainKubeNodePorts {
			for _, stat := range stats {
				s, err := table.ParseStat(stat)
				if err != nil {
					log.Warnf("parse stats error: %s", err)
					continue
				}
				// Options:/* archery/archery:web-http */ tcp dpt:30103
				opts := strings.Split(s.Options, " ")
				namespace := strings.Split(opts[1], "/")[0]
				name := strings.Split(strings.Split(opts[1], "/")[1], ":")[0]
				portname := strings.Split(strings.Split(opts[1], "/")[1], ":")[1]
				nodeport := strings.Split(opts[len(opts)-1], ":")[1]
				var target string
				if strings.Contains(s.Target, ChainKubeSvcPrefix) {
					target = s.Target
				}
				//if namespace != "kubestar" || name != "kubestar-qa" {
				//	continue
				//}

				//log.Infof("stat: %+v", s)
				//log.Infof("opt: %+v", opts)
				key := fmt.Sprintf("%s/%s", namespace, name)
				_, ok := servicesMap[key]
				if ok {
					existed := map[string]bool{}
					svc := servicesMap[key]
					//svc.Chain = target
					for idx, p := range svc.Ports {
						if p.Name == portname {
							svc.Ports[idx].NodePort = nodeport
							svc.Ports[idx].Chain = target
						}
						existed[p.Name] = true
					}

					if !existed[portname] {
						svc.Ports = append(svc.Ports, service.Port{
							Name:     portname,
							NodePort: nodeport,
						})
					}
					servicesMap[key] = svc
				} else {
					this := service.Service{
						Name:      name,
						Namespace: namespace,
						Ports:     []service.Port{},
						ChainNodePort: c,
						//Endpoints: []service.Endpoints{},
						//Chain:     target,
					}
					this.Ports = append(this.Ports, service.Port{
						Name:     portname,
						NodePort: nodeport,
						Chain: target,
					})
					servicesMap[key] = this
				}
			}
		}

		if c == ChainKubeServices {
			for _, stat := range stats {
				s, err := table.ParseStat(stat)
				if err != nil {
					log.Warnf("parse stats error: %s", err)
					continue
				}
				// {Packets:0 Bytes:0 Target:KUBE-SVC-ERIFXISQEP7F7OF4 Protocol:tcp Opt:-- Input:* Output:* Source:0.0.0.0/0 Destination:172.20.0.10/32 Options:/* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53}
				opts := strings.Split(s.Options, " ")
				namespace := strings.Split(opts[1], "/")[0]
				if strings.Contains(s.Options, "NOTE") {
					continue
				}
				name := strings.Split(strings.Split(opts[1], "/")[1], ":")[0]
				var target string
				if strings.Contains(s.Target, ChainKubeSvcPrefix) {
					target = s.Target
				}
				//if namespace != "kubestar" || name != "kubestar-qa" {
				//	continue
				//}

				//log.Infof("opt: %+v", opts)

				portname := strings.Split(strings.Split(opts[1], "/")[1], ":")[1]
				port := strings.Split(opts[len(opts)-1], ":")[1]
				clusterIP := s.Destination.IP.String()

				key := fmt.Sprintf("%s/%s", namespace, name)
				_, ok := servicesMap[key]
				if ok {
					existed := map[string]bool{}
					svc := servicesMap[key]
					svc.ClusterIP = clusterIP
					svc.ChainCluster = c
					//svc.Chain = target
					for idx, p := range svc.Ports {
						if p.Name == portname {
							svc.Ports[idx].Port = port
							svc.Ports[idx].Chain = target
							svc.Ports[idx].Endpoints = []string{}
						}
						existed[p.Name] = true
					}

					if !existed[portname] {
						svc.Ports = append(svc.Ports, service.Port{
							Name:      portname,
							Port:      port,
							Chain:     target,
							Endpoints: []string{},
						})
					}
					servicesMap[key] = svc
				} else {
					this := service.Service{
						Name:      name,
						Namespace: namespace,
						ClusterIP: clusterIP,
						ChainCluster: c,
						Ports:     []service.Port{},
						//Endpoints: []service.Endpoint{},
					}
					this.Ports = append(this.Ports, service.Port{
						Name: portname,
						Port: port,
						Chain: target,
						Endpoints: []string{},
					})
					servicesMap[key] = this
				}

			}
		}

		if strings.Contains(c, ChainKubeSvcPrefix) {
			for _, stat := range stats {
				s, err := table.ParseStat(stat)
				if err != nil {
					log.Warnf("parse stats error: %s", err)
					continue
				}
				//targetMap[c] = append(targetMap[c], )
				//	log.Infof("c stats: %+v", s)
				if targetMap[c] == nil {
					targetMap[c] = map[string]iptables.Stat{}
				}
				targetMap[c][s.Target] = s
				//log.Infof("targetMap: %+v", targetMap[c])
			}
		}
		//log.Infof("targetMap: %+v", targetMap)

		if strings.Contains(c, ChainKubeSepPrefix) {
			for _, stat := range stats {
				s, err := table.ParseStat(stat)
				if err != nil {
					log.Warnf("parse stats error: %s", err)
					continue
				}
				//log.Infof("c: %s", c)
				if s.Target == ChainDNAT {
					//log.Infof("endpoint stat: %+v", s)
					pod := strings.Split(strings.Split(s.Options, " ")[1], ":")[1:]
					endpointsMap[c] = strings.Join(pod, ":")
					//log.Infof("c: %s, endpointsMap: %+v", c, endpointsMap[c])
				}
				//podIP := strings.Split(strings.Split(s.Options, " ")[1], ":")[1]
				//podPort := strings.Split(strings.Split(s.Options, " ")[1], ":")[2]

				//endpointsMap[c] = stat
				//log.Infof("endpointsMap: %+v", endpointsMap)
			}

			//targetMap[c] = stats
			//for _, v := range targetMap {
			//log.Infof("v: %+v", v)
			//if c == "KUBE-SEP-4NRIM4M2HT6CMVBW" || c == "KUBE-SEP-YFXO2DQSNGGGTXIC" {
			//log.Infof("c: %s, stat: %+v", c, v[c])
			//}
			//stat := v[c]

			//}
		}
	}

	for _, v := range servicesMap {
		for i, p := range v.Ports {
			targets := targetMap[p.Chain]
			for k, _ := range targets {
				//log.Infof("k: %s, endpointsMap: %+v", k, endpointsMap[k])
				v.Ports[i].Endpoints = append(v.Ports[i].Endpoints,  endpointsMap[k])
			}
		}

		log.Infof("service: %+v", v)
		list.Items = append(list.Items, v)
	}

}
