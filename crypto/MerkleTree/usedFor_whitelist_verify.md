# 使用merkle tree空投，白名单验证
默克尔树，在区块链出现前，曾广泛用于文件系统和P2P系统中。<br />在区块链中，默克尔树常用于高效验证数据，如，实现空投，白名单，IDO，混币器等。<br />默克尔树是一种hash树，底层叶子节点的hash变动会一层一层的传递直到树根root，所以roothash实际代表了底层所有数据的摘要，通过验证roothash来确定是否是它的叶子节点。那么只需要在链上记录树根就可以开始验证其叶子节点的归属，每当新增叶子节点，也只需更新roothash即可，而不必存储整棵树，并且roothash的计算也可放在链下进行。<br />Merkle Tree在高效验证数据的同时减少了链上计算和存储，因为非常适合基于区块链的白名单验证，空投，IDO等需要验证数据的业务。
# JavaScript库
`npm install merkletreejs `
```
const { MerkleTree } = require('merkletreejs')
const SHA256 = require('crypto-js/sha256')

const leaves = ['a', 'b', 'c'].map(x => SHA256(x))
const tree = new MerkleTree(leaves, SHA256)
const root = tree.getRoot().toString('hex')
const leaf = SHA256('a')
const proof = tree.getProof(leaf)
console.log(tree.verify(proof, leaf, root)) // true

// print tree to console
console.log(tree.toString())


```
# 创建Merkle Tree
为配合solidity，选择使用keccak256；<br />`merkletree.getProof()`返回的是Array of objects；`merkletree.getHexProof()`返回的Proof array as hex strings，更适合作为参数传入合约
```
const { MerkleTree } = require('merkletreejs')
const keccak256 = require('keccak256')

let whitelist = [
    "0xBFb274470687a2e0BDBf02dA96d5221D4b27ea7b",
    "0x996735f0729bE271d6b23f27A4a37e62d88aEafc",
    "0x7bf729185445C5304BaD4B8c3ff6c78B4e1565Cd",
    "0x7FBCcdF96DB368bdb311576DEcD3f05B18663AEa",
    "0x7f9b403446eCDB6A42dA6DB5Ea523d59aed2112E",
    "0x97714d6AF3a1ead566D6851055d5402B53cD7954",
    "0xbbB016D2A0132C52AeE2EF328E3f5c0aD1a3C2Cd"
]

const leafNodes = whitelist.map(addr => keccak256(addr));
const merkletree = new MerkleTree(leafNodes, keccak256, {sortPairs: true});

const rootHash = merkletree.getRoot().toString('hex');
console.log("rootHash is: ", rootHash);
console.log(merkletree.toString());


// js验证白名单
console.log("--------verify------------");
const claimingAddr = keccak256("0xBFb274470687a2e0BDBf02dA96d5221D4b27ea7b");   // return a buffer
const proof = merkletree.getProof(claimingAddr)                             // returns the proof for a target leaf
console.log(proof);                                     // Array of objects
console.log(merkletree.verify(proof, claimingAddr, rootHash))       // true

// js验证白名单2
console.log("--------verify2------------");
const claimingAddr2 = leafNodes[0];                   // return a buffer
// console.log(claimingAddr == claimingAddr2);        // false     
// console.log(claimingAddr.toString() === claimingAddr2.toString());     // true   
const hexProof = merkletree.getHexProof(claimingAddr2);           // returns the proof for a target leaf as hex string
console.log(hexProof);                                // Proof array as hex strings    更适合作为参数传入合约
console.log(merkletree.verify(hexProof, claimingAddr2, rootHash));        // true

```
# 白名单验证
使用openzeppelin的MerkleProof.verify进行验证。<br />在合约中只需要存储roothash，验证时用户需传入默克尔树证明，新增叶子节点时，也只需要更新roothash。<br />验证通过后可领取空投，并将状态改为已领取，避免重复领取。
## 前端部分

1. 存储所有符合条件的地址，这样当用户访问站点时，可以立即查看他们是否符合条件；
2. 如果符合条件，再调用智能合约验证，并执行接下来的操作；
## 合约部分

1. 设置merkle树根，并提供验证接口；
2. 白名单地址可自行调用合约来领取空投；

在合约中只需要存储roothash，验证时用户需传入默克尔树证明。
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract WhiteListMerkle {
    // the root hash of merkletree
    // remember to provide this as a bytes32 type and not a string. 
    // 0x should be prepended.
    bytes32 public merkleRoot = 0xb63cec15d66cdcc08199c64a2105f32356c226151d1d1b43a6e9d68fb2e7684f;

    // mapping variable to mark whitelist address as having claimed.
    mapping(address => bool) public whitelistClaimed;

    // verify the provided _merkleProof
    function whitelist(bytes32[] calldata _merkleProof) public{
        require(!whitelistClaimed[msg.sender], "address has already claimed.");

        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        require(MerkleProof.verify(_merkleProof, merkleRoot, leaf), "Invaild proof.");

        whitelistClaimed[msg.sender] = true;
    }

    function setRootHash(bytes32 roothash_) external {
        merkleRoot = roothash_;
    }
}
```
# 合约交互
调用合约API进行验证，需传入默克尔树证明。merkletree.getHexProof()
```
const { ethers } = require("hardhat");

async function main() {
    const [owner, second] = await ethers.getSigners();
    console.log("owner address: ", owner.address);

    const WhiteListMerkle = await ethers.getContractFactory("WhiteListMerkle");
    const whiteListMerkle = await WhiteListMerkle.attach("0xE3EA30566ca0d2677360E29663f745dc7AD95F58");       // test

    // 0x should be prepended
    // const set_roothash = await whiteListMerkle.setRootHash("0xaf8c51b816be8428c9c03dcce6f9483a82033737361c9276aa2db3470dbbb780");
    // await set_roothash.wait();
    // console.log("set done.");

    // verify 
    // const merkleProof = [
    //     '0x497de751e77af5954dbcae3eba7c203606e8c52006fb1fcc2c0df507b976363a',
    //     '0x71249e6e1d6f7059bd2f07ab00601bade6fbd5ffd7c0d63b983cab0bc097bfe3',
    //     '0xa25d73d7d8dbcf73b7b71286c8de55451b4efa13be5bac629d7b2c966588ea0c'
    //   ]
    // const tx_verify = await whiteListMerkle.whitelist(merkleProof);
    // console.log(tx_verify);

    // view whitelistClaimed
    const view_claimed = await whiteListMerkle.whitelistClaimed(owner.address);
    console.log(view_claimed);
}
```
# merkle空投完整案例
```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleDistributor {
    address public immutable token;
    bytes32 public immutable merkleRoot;

    // This is a packed array of booleans.
    mapping(uint256 => uint256) private claimedBitMap;

    constructor(address token_, bytes32 merkleRoot_) {
        token = token_;
        merkleRoot = merkleRoot_;
    }

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);
    }

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external {
        require(!isClaimed(index), 'MerkleDistributor: Drop already claimed.');

        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(merkleProof, merkleRoot, node), 'MerkleDistributor: Invalid proof.');

        // Mark it claimed and send the token.
        _setClaimed(index);
        require(IERC20(token).transfer(account, amount), 'MerkleDistributor: Transfer failed.');

    }
}
```
