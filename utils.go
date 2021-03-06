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
)

func getIptable() (*iptables.IPTables, error) {
	return iptables.New()
}

func getChains(t *iptables.IPTables, table string)([]string, error)  {
	return t.ListChains(table)
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

func printChain(t *iptables.IPTables, table string, chain string) error {
	printChainHeader(chain)
	rules, err := getRules(t, table, chain)
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

