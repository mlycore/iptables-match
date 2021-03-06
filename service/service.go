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

package service

type Services struct {
	Items []Service
}

type Service struct {
	Name      string
	Namespace string
	ClusterIP string
	Ports     []Port
	ChainNodePort string
	ChainCluster string
	//Endpoints []Endpoints
	//Chain     string
}

type Port struct {
	Name       string
	Port       string
	TargetPort string
	NodePort   string
	Endpoints  []string
	Chain      string
}

type Endpoint struct {
	Pod       string
	Possibility string
}

func (s Service) BuildFromRules(rules []string) Service {
	return s
}
