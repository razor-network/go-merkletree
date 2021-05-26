// Copyright © 2018, 2019 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wealdtech/go-merkletree/keccak256"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

var (
	tests = []struct {
		// hash type to use
		hashType HashType
		// data to create the node
		data [][]byte
		// expected error when attempting to create the tree
		createErr error
		// root hash after the tree has been created
		root []byte
		// DOT representation of tree
		dot string
		// salt to use
		salt []byte
		// saltedRoot hash after the tree has been created with the salt
		saltedRoot []byte

		proof [][]byte
	}{
		{ // 1
			hashType: keccak256.New(),
			data: [][]byte{
				[]byte("foo"),
				[]byte("bar"),
				[]byte("crypto"),
				[]byte("blockchain"),
				[]byte("blockchain2"),
			},
			root:       _byteArray("112c317c3e220ed642772bc5f978adfb1cbe4b15ed3886b82472cdcf2b47ba2e"),
			dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"b608…16b7\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"c162…985f\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"fb6c…aeed\"];}",
			salt:       nil,
			saltedRoot: _byteArray("112c317c3e220ed642772bc5f978adfb1cbe4b15ed3886b82472cdcf2b47ba2e"),
			proof: [][]byte{
					_byteArray("435cd288e3694b535549c3af56ad805c149f92961bf84a1c647f7d86fc2431b4"),
					_byteArray("2835a32e1ec180d13dd744a7bd84e079e3421004fe7ce4a3ffffa071397020e3"),
					_byteArray("7fb7536841932e8f22b6d065824be1f7bb199461dfa7078f6a5a4efbe31840b7"),

					_byteArray("41b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d"),
					_byteArray("2835a32e1ec180d13dd744a7bd84e079e3421004fe7ce4a3ffffa071397020e3"),
					_byteArray("7fb7536841932e8f22b6d065824be1f7bb199461dfa7078f6a5a4efbe31840b7"),

					_byteArray("7ee156df5091fbef71b96557542210a9c9ca851cc85aaf60026519b4aaccf491"),
					_byteArray("744766909640c85c19ca00139e7af3c5d9cb8dbfbc6635812eedc4e3cbf4fce6"),
					_byteArray("7fb7536841932e8f22b6d065824be1f7bb199461dfa7078f6a5a4efbe31840b7"),

					_byteArray("35006686fd78b85ed3fb52493d70cb3f7732177a19f352814df621b506c237a4"),
					_byteArray("744766909640c85c19ca00139e7af3c5d9cb8dbfbc6635812eedc4e3cbf4fce6"),
					_byteArray("7fb7536841932e8f22b6d065824be1f7bb199461dfa7078f6a5a4efbe31840b7"),

					_byteArray("3b2fc67069ba712a771d190d98ba2f389a086efee7526f044fc18e404eb70131"),
			},
		},
		{ // 2
			hashType: keccak256.New(),
			data: [][]byte{
				math.U256Bytes(big.NewInt(0)),
				math.U256Bytes(big.NewInt(267984000000)),
				math.U256Bytes(big.NewInt(3986910000000)),
			},
			root:       _byteArray("bf5b1cfe51c06033cb5f9ff028bb06f3d0c14e27437ccad3e8a7ca40b5590b66"),
			dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"b608…16b7\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"c162…985f\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"fb6c…aeed\"];}",
			salt:       nil,
			saltedRoot: _byteArray("bf5b1cfe51c06033cb5f9ff028bb06f3d0c14e27437ccad3e8a7ca40b5590b66"),
			proof: [][]byte{
				_byteArray("32d4d7dfec7dd0785e80ad542750ed278072cc0d1c6294faec5e291d5aeed882"),
				_byteArray("bfa1a27b775ae321986b8a1c7d6935ea639dac39dab890a04e51558744998cb5"),

				_byteArray("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
				_byteArray("bfa1a27b775ae321986b8a1c7d6935ea639dac39dab890a04e51558744998cb5"),

				_byteArray("d88e98791f5ddb487beec9c66433caad21b838ce816302902da8a743db4c9b7e"),
			},
		},
		{ // 3
			hashType: keccak256.New(),
			data: [][]byte{
				math.U256Bytes(big.NewInt(0)),
				math.U256Bytes(big.NewInt(267984000000)),
				math.U256Bytes(big.NewInt(3986910000000)),
				math.U256Bytes(big.NewInt(11992)),
			},
			root:       _byteArray("3f22f9c030e959a219ce3792446213d9418a0d06ea78e71462ace248c9021adf"),
			dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"b608…16b7\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"c162…985f\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"fb6c…aeed\"];}",
			salt:       nil,
			saltedRoot: _byteArray("3f22f9c030e959a219ce3792446213d9418a0d06ea78e71462ace248c9021adf"),
			proof: [][]byte{
				_byteArray("32d4d7dfec7dd0785e80ad542750ed278072cc0d1c6294faec5e291d5aeed882"),
				_byteArray("c1195dd64f78c947f88ae3b644e1149aad6267308cafd55008cd88da18bd22ca"),

				_byteArray("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
				_byteArray("c1195dd64f78c947f88ae3b644e1149aad6267308cafd55008cd88da18bd22ca"),

				_byteArray("ac05abcc4e30ff7d8c26d763ec77f8fd90448dbb463344095cac865bb0727f80"),
				_byteArray("d88e98791f5ddb487beec9c66433caad21b838ce816302902da8a743db4c9b7e"),

				_byteArray("bfa1a27b775ae321986b8a1c7d6935ea639dac39dab890a04e51558744998cb5"),
				_byteArray("d88e98791f5ddb487beec9c66433caad21b838ce816302902da8a743db4c9b7e"),
			},
		},
		{ // 4
			hashType: keccak256.New(),
			data: [][]byte{
				math.U256Bytes(big.NewInt(0)),
				math.U256Bytes(big.NewInt(267984000000)),
				math.U256Bytes(big.NewInt(3986910000000)),
				[]byte("foo"),
				[]byte("bar"),
				[]byte("crypto"),
				[]byte("blockchain"),
			},
			root:       _byteArray("21ec5637a45e6dab29cce81a3c472e99d50dcb0250d82f56da4dc02820c2c84e"),
			dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"b608…16b7\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"c162…985f\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"fb6c…aeed\"];}",
			salt:       nil,
			saltedRoot: _byteArray("21ec5637a45e6dab29cce81a3c472e99d50dcb0250d82f56da4dc02820c2c84e"),
			proof: [][]byte{

				_byteArray("32d4d7dfec7dd0785e80ad542750ed278072cc0d1c6294faec5e291d5aeed882"),
				_byteArray("e802a2ded69d6aea09be7d205756630116a2ac81c962f737953e9a7941923f76"),
				_byteArray("f9933da9ed5dbb0517f868ef6065e33713799c61be77cd08f40becbadc87a2b1"),

				_byteArray("290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
				_byteArray("e802a2ded69d6aea09be7d205756630116a2ac81c962f737953e9a7941923f76"),
				_byteArray("f9933da9ed5dbb0517f868ef6065e33713799c61be77cd08f40becbadc87a2b1"),

				_byteArray("41b1a0649752af1b28b3dc29a1556eee781e4a4c3a1f7f53f90fa834de098c4d"),
				_byteArray("d88e98791f5ddb487beec9c66433caad21b838ce816302902da8a743db4c9b7e"),
				_byteArray("f9933da9ed5dbb0517f868ef6065e33713799c61be77cd08f40becbadc87a2b1"),

				_byteArray("bfa1a27b775ae321986b8a1c7d6935ea639dac39dab890a04e51558744998cb5"),
				_byteArray("d88e98791f5ddb487beec9c66433caad21b838ce816302902da8a743db4c9b7e"),
				_byteArray("f9933da9ed5dbb0517f868ef6065e33713799c61be77cd08f40becbadc87a2b1"),

				_byteArray("35006686fd78b85ed3fb52493d70cb3f7732177a19f352814df621b506c237a4"),
				_byteArray("7ee156df5091fbef71b96557542210a9c9ca851cc85aaf60026519b4aaccf491"),
				_byteArray("9d98ede07d0edebd2f7c237a2d576fc76b948423b29ab64d6b65fff401272990"),

				_byteArray("435cd288e3694b535549c3af56ad805c149f92961bf84a1c647f7d86fc2431b4"),
				_byteArray("7ee156df5091fbef71b96557542210a9c9ca851cc85aaf60026519b4aaccf491"),
				_byteArray("9d98ede07d0edebd2f7c237a2d576fc76b948423b29ab64d6b65fff401272990"),

				_byteArray("45b31150745292e43a4018373898f817f95f87fc1cb80d542d9300857ac2042a"),
				_byteArray("9d98ede07d0edebd2f7c237a2d576fc76b948423b29ab64d6b65fff401272990"),

			},
		},
	}
)

func TestNewUsingV1(t *testing.T) {
	for i, test := range tests {
		tree, err := NewUsingV1(test.data, test.hashType, nil)
		if test.createErr != nil {
			assert.Equal(t, test.createErr, err, fmt.Sprintf("expected error at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.root, tree.RootV1(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestGenerateProofV1(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsingV1(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			index := 0
			for j, _ := range test.data {
				proof, err := tree.GenerateProofV1(j)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				for _, p := range proof.Hashes {
					assert.Equal(t, p, test.proof[index],fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
					index++
				}
			}
		}
	}
}

func TestSaltedProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.salt != nil {
			tree, err := NewUsing(test.data, test.hashType, test.salt)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.saltedRoot, tree.RootV1(), fmt.Sprintf("unexpected root at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProofV1(j)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, tree.Root(), test.hashType, test.salt)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestMissingProof(t *testing.T) {
	missingData := []byte("missing")
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, err = tree.GenerateProof(missingData)
			assert.Equal(t, err, errors.New("data not found"))
		}
	}

}

//const _letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
//const _letterslen = len(_letters)
//
//func _randomString(n int) string {
//	res := make([]byte, n)
//	for i := range res {
//		res[i] = _letters[rand.Int63()%int64(_letterslen)]
//	}
//	return string(res)
//}
//
//func TestProofRandom(t *testing.T) {
//	data := make([][]byte, 1000)
//	for i := 0; i < 1000; i++ {
//		data[i] = []byte(_randomString(6))
//	}
//	tree, err := New(data)
//	assert.Nil(t, err, "failed to create tree")
//	for i := range data {
//		proof, err := tree.GenerateProof(data[i])
//		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
//		proven, err := VerifyProof(data[i], proof, tree.Root())
//		assert.True(t, proven, fmt.Sprintf("failed to verify proof at data %d", i))
//	}
//}
//
//func TestString(t *testing.T) {
//	for i, test := range tests {
//		if test.createErr == nil {
//			tree, err := NewUsing(test.data, test.hashType, nil)
//			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
//			assert.Equal(t, fmt.Sprintf("%x", test.root), tree.String(), fmt.Sprintf("incorrect string representation at test %d", i))
//		}
//	}
//}
//
//func TestDOT(t *testing.T) {
//	for i, test := range tests {
//		if test.createErr == nil {
//			tree, err := NewUsing(test.data, test.hashType, nil)
//			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
//			assert.Equal(t, test.dot, tree.DOT(new(StringFormatter), nil), fmt.Sprintf("incorrect DOT representation at test %d", i))
//		}
//	}
//}
//
//func TestFormatter(t *testing.T) {
//	tree, err := New(tests[5].data)
//	assert.Nil(t, err, "failed to create tree")
//	assert.Equal(t, "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"466f…6f6f\" [shape=oval];\"466f…6f6f\"->4;4 [label=\"7b50…c81f\"];4->2;\"4261…6172\" [shape=oval];\"4261…6172\"->5;5 [label=\"03c7…6406\"];4->5 [style=invisible arrowhead=none];5->2;\"4261…617a\" [shape=oval];\"4261…617a\"->6;6 [label=\"6d5f…2ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000…0000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"13c7…a929\"];3->1;2 [label=\"e9e0…f637\"];2->1;1 [label=\"635c…889c\"];}", tree.DOT(nil, nil), "incorrect default representation")
//	assert.Equal(t, "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"466f6f\" [shape=oval];\"466f6f\"->4;4 [label=\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"];4->2;\"426172\" [shape=oval];\"426172\"->5;5 [label=\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"];4->5 [style=invisible arrowhead=none];5->2;\"42617a\" [shape=oval];\"42617a\"->6;6 [label=\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000000000000000000000000000000000000000000000000000000000000000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"13c75aad6074ad17d7014b1ee42012c840e90a79eb8e1694e3b107ca6ae8a929\"];3->1;2 [label=\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"];2->1;1 [label=\"635ca493fe20a7b8485d2e4c650e33444664b4ce0773c36d2a9da79176f6889c\"];}", tree.DOT(new(HexFormatter), new(HexFormatter)), "incorrect default representation")
//}
