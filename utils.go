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
	"github.com/mlycore/log"
)

func getIptable() (*iptables.IPTables, error) {
	return iptables.New()
}

func getChains(t *iptables.IPTables, table string) ([]Chain, error) {
	cs, err := t.ListChains(table)
	if err != nil {
		log.Errorf("get chains error: %s", err)
		return nil, err
	}
	chains := []Chain{}
	for _, c := range cs {
		cm := ChainMeta{ChainName: c, Rules: []Rule{}, Stats: []iptables.Stat{}}
		rules, err := getRules(t, table, c)
		statsCol, err := t.Stats(table, c)
		if err != nil {
			log.Warnf("get rules error: %s", err)
			continue
		}
		for _, r := range rules {
			cm.Rules = append(cm.Rules, Rule{Raw: r})
		}

		for _, s := range statsCol {
			stat, err := t.ParseStat(s)
			if err != nil {
				log.Warnf("parse error: %s", err)
				//continue
			}
			cm.Stats = append(cm.Stats, stat)
		}

		var ch Chain
		switch c {
		case ChainKubeServices:
			{
				ch = &KubeServices{cm}
				chains = append(chains, ch)
			}
		case ChainKubeExternalServices:
			{
				ch = &KubeExternalServices{cm}
				chains = append(chains, ch)
			}
		case ChainKubeForward:
			{
				ch = &KubeForward{cm}
				chains = append(chains, ch)
			}
		case ChainKubeMarkDrop:
			{
				ch = &KubeMarkDrop{cm}
				chains = append(chains, ch)
			}
		case ChainKubeMarkMasq:
			{
				ch = &KubeMarkMasq{cm}
				chains = append(chains, ch)
			}
		case ChainKubeNodePorts:
			{
				ch = &KubeNodePorts{cm}
				chains = append(chains, ch)
			}
		case ChainKubePostRouting:
			{
				ch = &KubePostRouting{cm}
				chains = append(chains, ch)
			}
		}
	}

	return chains, nil
}

func getRules(t *iptables.IPTables, table string, chain string) ([]string, error) {
	return t.List(table, chain)
	//return t.ListWithCounters(table, chain)
}

func printTableHeader(table string) {
	fmt.Printf("\n\n------ Table %s ------\n\n", table)
}

func printChainHeader(chain string) {
	fmt.Printf("\n------ Chain %s ------\n", chain)
}

func printRule(r string) {
	fmt.Println(r)
}

func printChain(t *iptables.IPTables, table string, chain Chain) error {
	printChainHeader(chain.Name())
	rules, err := getRules(t, table, chain.Name())
	if err != nil {
		return err
	}
	for _, r := range rules {
		printRule(r)
	}
	return nil
}

func printTable(t *iptables.IPTables, table string) error {
	printTableHeader(table)
	chains, err := getChains(t, table)
	if err != nil {
		return err
	}
	for _, c := range chains {
		printChain(t, table, c)
	}

	return nil
}

func handleTable(t *iptables.IPTables, table string) error {
	servicesMap := map[string]Service{}
	chains, err := getChains(t, table)
	if err != nil {
		return err
	}
	for _, c := range chains {
		log.Infof("chain %s", c.Name())
		services := c.Handle()
		if c.Name() == ChainKubeNodePorts {
			for _, svc := range services.Items {
				key := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
				servicesMap[key] = Service{
					Name:      svc.Name,
					Namespace: svc.Namespace,
					ClusterIP: "",
					Port:      "",
					NodePort:  svc.NodePort,
					Endpoints: nil,
				}
			}
		}
		if c.Name() == ChainKubeServices {
			for _, svc := range services.Items {
				key := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
				ns := Service{
					Name:      svc.Name,
					Namespace: svc.Namespace,
					ClusterIP: svc.ClusterIP,
					Port:      svc.Port,
					NodePort:  servicesMap[key].NodePort,
					Endpoints: nil,
				}
				servicesMap[key] = ns
			}
		}
		//c.Print()
	}
	for _, svc := range servicesMap {
		log.Infof("service: %+v", svc)
	}

	return nil
}
