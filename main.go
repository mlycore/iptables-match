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
	"github.com/mlycore/log"
)

func main()  {
	table, err := getIptable()
	if err != nil {
		log.Fatalf("%+v", err)
	}

	for _, t := range []string{TableMangle, TableFilter, TableNat} {
		err = printTable(table, t)
		if err != nil {
			log.Errorf("print table %s error: %s", t, err)
		}
	}
}
