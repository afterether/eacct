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
/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import "unsafe"
import (
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"encoding/hex"
	"encoding/json"
	"strings"
	"strconv"
	"fmt"
	"errors"
	crand "crypto/rand"
)
type AET_Transaction_t struct {
	Nonce			uint64		`json: "dst_addr"       gencodec:"required"`
	Hash			string		`json: "hash"			gencodec:"required"`
	Src_addr		string		`json: "src_addr"       gencodec:"required"`
	Dst_addr		string		`json: "dst_addr"       gencodec:"required"`
	Value			string		`json: "value"			gencodec:"required"`
	Gas_limit		string		`json: "gas_limit"      gencodec:"required"`
	Gas_price		string		`json: "gas_price"      gencodec:"required"`
	Extra_data		string		`json: "extra_data"     gencodec:"required"`
}
func write_back_error(output unsafe.Pointer,output_len *C.int,err error) {

	error_str:=err.Error();
	error_str_bytes:=[]byte(error_str)
	length:=_Ctype_ulong(len(error_str_bytes))
	*output_len=C.int(length)
	c_bytes:=C.CBytes(error_str_bytes)
	C.memcpy(output,c_bytes,length)
	C.free(c_bytes)
}
//export Generate_account
func Generate_account(out_account_addr_ptr unsafe.Pointer, out_private_key_ptr unsafe.Pointer, out_error_str unsafe.Pointer) C.int {
	// out_account_addr_ptr			pre-allocated 20 byte buffer to store account address
	// out_private_key_ptr			pre-allocated byte buffer to store private key

	key, err := keystore.NewKey(crand.Reader)
	if err!=nil {
		error_str:=err.Error();
		error_str=error_str+"\x00";		// convert to C string (null terminated)
		length:=_Ctype_ulong(len(error_str))
		error_str_bytes:=[]byte(error_str)
		c_bytes:=C.CBytes(error_str_bytes)
		C.memcpy(out_error_str,c_bytes,length)
		C.free(c_bytes)
		return 1;
	}

	address:=hex.EncodeToString(key.Address.Bytes());
	private_key:=hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))

	var c_bytes unsafe.Pointer

	c_bytes=C.CBytes([]byte(address));
	C.memcpy(out_account_addr_ptr,c_bytes,_Ctype_ulong(len(address)))
	C.free(c_bytes)

	c_bytes=C.CBytes([]byte(private_key))
	C.memcpy(out_private_key_ptr,c_bytes,_Ctype_ulong(len(private_key)))
	C.free(c_bytes)

	return 0;
}
//export Generate_key
func Generate_key(out_key_json unsafe.Pointer, output_len *C.int, out_error_str unsafe.Pointer) C.int {
	// out_key_json			buffer to write the json string, must be allocated before calling here
	// output_len			the length of the error string or json string (containing the key) that was written
	// out_error_str		if error occurs, this buffer is filled with error string, must be pre-allocated from C

	key, err := keystore.NewKey(crand.Reader)
	if err!=nil {
		error_str:=err.Error();
		error_str_bytes:=[]byte(error_str)
		length:=_Ctype_ulong(len(error_str_bytes))
		*output_len=C.int(length);
		c_bytes:=C.CBytes(error_str_bytes)
		C.memcpy(out_error_str,c_bytes,length)
		C.free(c_bytes)
		return 1;
	}

	if key == nil {
		error_str_bytes:=[]byte("Null key received, this should never happen, something is wrong")
		length:=_Ctype_ulong(len(error_str_bytes))
		*output_len=C.int(length)
		c_bytes:=C.CBytes(error_str_bytes)
		C.memcpy(out_error_str,c_bytes,length)
		C.free(c_bytes)
		return 1;
	}

	json_data,err:=key.MarshalJSON();
	if err!=nil {
		error_str:=err.Error();
		error_str_bytes:=[]byte(error_str)
		length:=_Ctype_ulong(len(error_str_bytes))
		*output_len=C.int(length)
		c_bytes:=C.CBytes(error_str_bytes)
		C.memcpy(out_error_str,c_bytes,length)
		C.free(c_bytes)
		return 1;
	}

	json_data_bytes:=[]byte(json_data);
	length:=_Ctype_ulong(len(json_data_bytes))
	*output_len=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(json_data_bytes)
	C.memcpy(out_key_json,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
//export Encrypt_key
func Encrypt_key(out_encrypted_key unsafe.Pointer,output_len_ptr *C.int,in_unencrypted_key unsafe.Pointer,input_len C.int,in_password *C.char) C.int {
	var	key keystore.Key

	unencrypted_key:=C.GoBytes(in_unencrypted_key, input_len)
	err:=key.UnmarshalJSON(unencrypted_key)
	if err!=nil {
		write_back_error(out_encrypted_key,output_len_ptr,err)
		return 1
	}

	password:=C.GoString(in_password)

	key_json, err := keystore.EncryptKey(&key, password , keystore.StandardScryptN, keystore.StandardScryptP)
	if err!=nil {
		write_back_error(out_encrypted_key,output_len_ptr,err)
		return 1
	}

	key_json_bytes:=[]byte(key_json)
	length:=_Ctype_ulong(len(key_json_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(key_json_bytes)
	C.memcpy(out_encrypted_key,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
//export Bigint_Add
func Bigint_Add(out_result unsafe.Pointer,output_len_ptr *C.int,in_elt1 *C.char,in_elt2 *C.char) {
	// receives 2 Big integers in string format, sums them and returns them as string

	elt1:=C.GoString(in_elt1)
	elt2:=C.GoString(in_elt2)

	big_elt1:=big.NewInt(0)
	big_elt1.SetString(elt1,10);
	big_elt2:=big.NewInt(0)
	big_elt2.SetString(elt2,10);

	big_sum:=big.NewInt(0);
	big_sum.Add(big_elt1,big_elt2)

	sum_bytes:=[]byte(big_sum.String())
	length:=_Ctype_ulong(len(sum_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(sum_bytes)
	C.memcpy(out_result,c_bytes,length)
	C.free(c_bytes)

}
//export Bigint_Sub
func Bigint_Sub(out_result unsafe.Pointer,output_len_ptr *C.int,in_elt1 *C.char,in_elt2 *C.char) {
	// receives 2 Big integers in string format, substracts first from the second and returns iresult as string

	elt1:=C.GoString(in_elt1)
	elt2:=C.GoString(in_elt2)

	big_elt1:=big.NewInt(0)
	big_elt1.SetString(elt1,10);
	big_elt2:=big.NewInt(0)
	big_elt2.SetString(elt2,10);

	big_sum:=big.NewInt(0);
	big_sum.Sub(big_elt1,big_elt2)

	sum_bytes:=[]byte(big_sum.String())
	length:=_Ctype_ulong(len(sum_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(sum_bytes)
	C.memcpy(out_result,c_bytes,length)
	C.free(c_bytes)

}
//export Bigint_Mul
func Bigint_Mul(out_result unsafe.Pointer,output_len_ptr *C.int,in_elt1 *C.char,in_elt2 *C.char) {
	// receives 2 Big integers in string format, substracts first from the second and returns iresult as string

	elt1:=C.GoString(in_elt1)
	elt2:=C.GoString(in_elt2)

	big_elt1:=big.NewInt(0)
	big_elt1.SetString(elt1,10);
	big_elt2:=big.NewInt(0)
	big_elt2.SetString(elt2,10);

	big_sum:=big.NewInt(0);
	big_sum.Mul(big_elt1,big_elt2)

	sum_bytes:=[]byte(big_sum.String())
	length:=_Ctype_ulong(len(sum_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(sum_bytes)
	C.memcpy(out_result,c_bytes,length)
	C.free(c_bytes)

}
//export Bigint_Cmp
func Bigint_Cmp(in_elt1 *C.char,in_elt2 *C.char) C.int {
	// receives 2 Big integers in string format, compares them and return -1,0,+1 

	elt1:=C.GoString(in_elt1)
	elt2:=C.GoString(in_elt2)

	big_elt1:=big.NewInt(0)
	big_elt1.SetString(elt1,10);
	big_elt2:=big.NewInt(0)
	big_elt2.SetString(elt2,10);

	result:=big_elt1.Cmp(big_elt2)
	return C.int(result)
}
//export NewKeyFromECDSA
func NewKeyFromECDSA(out_key_json unsafe.Pointer,output_len_ptr *C.int,in_private_key *C.char) C.int {

	private_key_str:=C.GoString(in_private_key);
	private_key,err:=crypto.HexToECDSA(private_key_str)

	if err!=nil {
		write_back_error(out_key_json,output_len_ptr,err)
		return 1;
	}

	key:=keystore.NewKeyFromECDSA(private_key);

	json_data,err:=key.MarshalJSON();
	if err!=nil {
		write_back_error(out_key_json,output_len_ptr,err)
		return 1;
	}

	json_data_bytes:=[]byte(json_data);
	length:=_Ctype_ulong(len(json_data_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(json_data_bytes)
	C.memcpy(out_key_json,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
//export DecryptKeyFromJSON
func DecryptKeyFromJSON(out_unencrypted_key_json unsafe.Pointer,output_len_ptr *C.int,in_encrypted_key_json *C.char,in_password *C.char) C.int {

	password:=C.GoString(in_password)
	encrypted_key:=C.GoString(in_encrypted_key_json)
	encrypted_key_bytes:=[]byte(encrypted_key)

	key,err:=keystore.DecryptKey(encrypted_key_bytes,password)
	if err!=nil {
		write_back_error(out_unencrypted_key_json,output_len_ptr,err)
		return 1;
	}

	json_data,err:=key.MarshalJSON();
	if err!=nil {
		write_back_error(out_unencrypted_key_json,output_len_ptr,err)
		return 1;
	}

	json_data_bytes:=[]byte(json_data);
	length:=_Ctype_ulong(len(json_data_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(json_data_bytes)
	C.memcpy(out_unencrypted_key_json,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
//export SignTransaction
func SignTransaction(out_signed_transaction unsafe.Pointer,output_len_ptr *C.int,out_hash unsafe.Pointer,in_encrypted_key_json *C.char,in_password *C.char,in_chain_id C.int,in_dst_addr *C.char,in_value *C.char,in_nonce C.int,in_gas_price *C.char,in_gas_limit *C.char,in_extra_data_hex *C.char) C.int {


	password:=C.GoString(in_password)
	encrypted_key:=C.GoString(in_encrypted_key_json)
	encrypted_key_bytes:=[]byte(encrypted_key)

	key,err:=keystore.DecryptKey(encrypted_key_bytes,password)
	if err!=nil {
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}

	zero:=big.NewInt(0)

	if (in_chain_id<0) {
		err:=errors.New("Invalid 'chain id', must be a positive number")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}
	chain_id:=big.NewInt(int64(in_chain_id))
	nonce:=uint64(in_nonce)
	if (nonce<0) {
		err:=errors.New("Negative nonce")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}

	dst_addr_str:=C.GoString(in_dst_addr)
	dst_addr:=common.HexToAddress(dst_addr_str)

	value_str:=C.GoString(in_value)
	value:=big.NewInt(0);
	_,ret:=value.SetString(value_str,10)
	if !ret {
		err:=errors.New("Value is not a number")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}
	if zero.Cmp(value)>0 {
		err:=errors.New("Value can't be negative")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}

	gas_limit_str:=C.GoString(in_gas_limit)
	gas_limit,err:=strconv.ParseUint(gas_limit_str,10,64);
	if err!=nil {
		err=errors.New("Gas limit is not a number")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}
	if gas_limit<1 {
		err:=errors.New("'Gas limit' can't be zero")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}

	gas_price_str:=C.GoString(in_gas_price)
	gas_price:=big.NewInt(0);
	_,ret=gas_price.SetString(gas_price_str,10)
	if !ret {
		err:=errors.New("'Gas price' is not a number")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}
	if zero.Cmp(gas_price)>0 {
		err:=errors.New("'Gas price' can't be negative")
		write_back_error(out_signed_transaction,output_len_ptr,err)
		return 1
	}
	var extra_data []byte
	extra_data_hex_str:=C.GoString(in_extra_data_hex)
	if len(extra_data_hex_str) > 0 {
		if len(extra_data_hex_str) < 3 {
			err:=errors.New("If `extra data` is provided as parameter to transaction, it must be longer than 2 characters")
			write_back_error(out_signed_transaction,output_len_ptr,err)
			return 1
		}
		if (extra_data_hex_str[0]=='0') && (extra_data_hex_str[1]=='x') {
			// extra data is valid
		} else {
			err:=errors.New("'extra data' is not in HEX format, please prepend 0x prefix")
			write_back_error(out_signed_transaction,output_len_ptr,err)
			return 1
		}
		var err error
		extra_data,err=hexutil.Decode(extra_data_hex_str)
		if err!=nil {
			write_back_error(out_signed_transaction,output_len_ptr,err)
			return 1
		}
	}

	unsigned_tx:=types.NewTransaction(nonce,dst_addr,value,gas_limit,gas_price,extra_data)
	signer := types.NewEIP155Signer(chain_id)
	signed_tx, _:= types.SignTx(unsigned_tx, signer, key.PrivateKey)

	hash:=signed_tx.Hash()
	hash_str:=hex.EncodeToString(hash.Bytes())

	tx_arr:=types.Transactions{signed_tx}
	raw_tx:= tx_arr.GetRlp(0)
	raw_tx_str:=hex.EncodeToString(raw_tx)

	raw_tx_bytes:=[]byte(raw_tx_str);
	length:=_Ctype_ulong(len(raw_tx_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(raw_tx_bytes)
	C.memcpy(out_signed_transaction,c_bytes,length)
	C.free(c_bytes)

	raw_hash_bytes:=[]byte(hash_str);
	c_bytes=C.CBytes(raw_hash_bytes)
	C.memcpy(out_hash,c_bytes,64)
	C.free(c_bytes)

	return 0;
}
//export DecodeTransaction
func DecodeTransaction(out_transaction_json unsafe.Pointer,output_len_ptr *C.int,in_encoded_tx *C.char,in_chain_id C.int) C.int {
	// out_src_addr must be a 40 byte memory location for the address of the signer

	encoded_tx_str:=C.GoString(in_encoded_tx)
	var tx *types.Transaction
	raw_tx,err := hex.DecodeString(encoded_tx_str)
	if err!=nil {
		write_back_error(out_transaction_json,output_len_ptr,err)
		return 1;
	}
	err=rlp.DecodeBytes(raw_tx, &tx)
	if err!=nil {
		write_back_error(out_transaction_json,output_len_ptr,err)
		return 1;
	}

	// get the signer of transaction
	chain_id:=big.NewInt(int64(in_chain_id))
	signer:=types.NewEIP155Signer(chain_id)
	src_addr,err:=signer.Sender(tx)
	if err!=nil {
		write_back_error(out_transaction_json,output_len_ptr,err)
		return 1;
	}

	// encode to JSON
	out_tx:=AET_Transaction_t {
		Hash:			hex.EncodeToString(tx.Hash().Bytes()),
		Src_addr:		hex.EncodeToString(src_addr.Bytes()),
		Dst_addr:		hex.EncodeToString(tx.To().Bytes()),
		Nonce:			tx.Nonce(),
		Value:			tx.Value().String(),
		Gas_limit:		strconv.FormatUint(tx.Gas(),10),
		Gas_price:		tx.GasPrice().String(),
		Extra_data:		hex.EncodeToString(tx.Data()),
	}

	json_data,err:=json.Marshal(out_tx)
	if err!=nil {
		write_back_error(out_transaction_json,output_len_ptr,err)
		return 1;
	}

	json_data_bytes:=[]byte(json_data);
	length:=_Ctype_ulong(len(json_data_bytes))
	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(json_data_bytes)
	C.memcpy(out_transaction_json,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
func param_decode(param string,arg *abi.Argument) (v interface{},err error) {
	param=strings.TrimSpace(param)
	switch(arg.Type.T) {
		case abi.StringTy:
			str_val:=new(string)
			v=str_val
			err=json.Unmarshal([]byte(param),v)
		case abi.UintTy,abi.IntTy:
			val:=big.NewInt(0)
			_,success:=val.SetString(param,10)
			if !success {
				err=errors.New(fmt.Sprintf("Invalid numeric (base 10) value: %v",param))
			}
			v=val
		case abi.AddressTy:
			if !((len(param)==(common.AddressLength*2+2)) || (len(param)==common.AddressLength*2)) {
				err=errors.New(fmt.Sprintf("Invalid address length (%v), must be 40 (unprefixed) or 42 (prefixed) chars",len(param)))
			} else {
				var addr common.Address
				if len(param)==(common.AddressLength*2+2) {
					addr=common.HexToAddress(param)
				} else {
					var data []byte
					data,err=hex.DecodeString(param)
					if err!=nil {
					}
					addr.SetBytes(data)
				}
				v=addr
			}
		case abi.HashTy:
			if !((len(param)==(common.HashLength*2+2)) || (len(param)==common.HashLength*2)) {
				err=errors.New(fmt.Sprintf("Invalid hash length, must be 64 (unprefixed) or 66 (prefixed) chars"))
			} else {
				var hash common.Hash
				if len(param)==(common.HashLength*2+2) {
					hash=common.HexToHash(param)
				} else {
					var data []byte
					data,err=hex.DecodeString(param)
					hash.SetBytes(data)
				}
				v=hash
			}
		case abi.BytesTy:
			if len(param)>2 {
				if (param[0]=='0') && (param[1]=='x') {
					param=param[2:]			// cut 0x prefix
				}
			}
			decoded_bytes,tmperr:=hex.DecodeString(param)
			v=decoded_bytes
			err=tmperr
		case abi.BoolTy:
			val:=new(bool)
			v=val
			err=json.Unmarshal([]byte(param),v)
		default:
			err=errors.New(fmt.Sprintf("Not supported parameter type: %v",arg.Type))
	}
	return v,err
}
//export EncodeInput4ContractCall
func EncodeInput4ContractCall(out_encoded_input unsafe.Pointer,output_len_ptr *C.int,in_output_max_len C.int,in_contract_abi *C.char,in_method_name *C.char,in_method_params *C.char) C.int {

	contract_abi_str:=C.GoString(in_contract_abi)
	method_name:=C.GoString(in_method_name)
	method_params_str:=C.GoString(in_method_params)

	contract_abi,err:=abi.JSON(strings.NewReader(contract_abi_str))
	if err!=nil {
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1;
	}
	method,exists:=contract_abi.Methods[method_name]
	if !exists {
		err:=errors.New(fmt.Sprintf("Method '%v' not found in the ABI",method_name))
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1
	}
	params:=strings.Split(method_params_str,",")
	if len(params)!=len(method.Inputs) {
		err:=errors.New(fmt.Sprintf("Invalid number of parameters. Method requires %v, but %v provided",len(method.Inputs),len(params)))
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1
	}
	method_params:=make([]interface{},0,8)
	for i,input:=range method.Inputs {
		v,err:=param_decode(params[i],&input)
		if err!=nil {
			err:=errors.New(fmt.Sprintf("Failed to decode parameter %v (%v): %v",(i+1),input.Name,err))
			write_back_error(out_encoded_input,output_len_ptr,err)
			return 1
		}
		method_params=append(method_params,v)
	}

	encoded_input,err:=contract_abi.Pack(method_name,method_params...)
	if err!=nil {
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1;
	}
	encoded_input_hex:=hex.EncodeToString(encoded_input)

	output_bytes:=[]byte(encoded_input_hex);
	length:=_Ctype_ulong(len(output_bytes))
	if (length>_Ctype_ulong(in_output_max_len)) {
		err:=errors.New(fmt.Sprintf("Output buffer too small for generated output (%v>%v)",length,in_output_max_len))
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1
	}

	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(output_bytes)
	C.memcpy(out_encoded_input,c_bytes,length)
	C.free(c_bytes)

	return 0;
}
//export ABI_Methods
func ABI_Methods(out_encoded_input unsafe.Pointer,output_len_ptr *C.int,in_output_max_len C.int,in_contract_abi *C.char) C.int {

	contract_abi_str:=C.GoString(in_contract_abi)
	contract_abi,err:=abi.JSON(strings.NewReader(contract_abi_str))
	if err!=nil {
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1;
	}
	method_list:=""
	for m:=range contract_abi.Methods {
		if len(method_list)>0 {
			method_list=method_list+","
		}
		method_list=method_list+m
	}

	output_bytes:=[]byte(method_list);
	length:=_Ctype_ulong(len(output_bytes))
	if (length>_Ctype_ulong(in_output_max_len)) {
		err:=errors.New(fmt.Sprintf("Output buffer too small for generated output (%v>%v)",length,in_output_max_len))
		write_back_error(out_encoded_input,output_len_ptr,err)
		return 1
	}

	*output_len_ptr=C.int(length)

	var c_bytes unsafe.Pointer
	c_bytes=C.CBytes(output_bytes)
	C.memcpy(out_encoded_input,c_bytes,length)
	C.free(c_bytes)

	return 0;

}
func main() {}
