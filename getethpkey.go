/*
	Copyright 2018 The AfterEther Team
	This file is part of the EthBot, Ethereum Blockchain -> SQL converter.
		
	EthBot is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	EthBot is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public License
	along with EthBot. If not, see <http://www.gnu.org/licenses/>.
*/
package main

import (
	"bufio"
	"fmt"
	"os"
	"io/ioutil"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"encoding/hex"
)
func main() {
	if len(os.Args)<2 {
		fmt.Println(fmt.Sprintf("usage: %v JSON_account_file",os.Args[0]))
		return
	}
	encrypted_key, err := ioutil.ReadFile(os.Args[1])
	if err!=nil {
		fmt.Println(fmt.Sprintf("Error reading file: %v",err))
		return
	}
	fmt.Println("WARNING: Password will be echoed in clear text to stdout, as you type it. (hiding it is a TODO)")
    reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	
	password=password[:len(password)-1]
	encrypted_key_bytes:=[]byte(encrypted_key)
	key,err:=keystore.DecryptKey(encrypted_key_bytes,password)
    if err!=nil {
		fmt.Println(fmt.Sprintf("Error decrypting key: %v",err))
		return
	}
	private_key:=hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))
	fmt.Println(fmt.Sprintf("Private Key: %v",private_key))
}
