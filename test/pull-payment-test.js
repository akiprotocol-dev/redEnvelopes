const { ethers } = require("hardhat");
const chai = require("chai");
const { solidity } = require("ethereum-waffle");
const keccak256 = require('keccak256');
const { BigNumber } = require("@ethersproject/bignumber");
chai.use(solidity);
const { expect } = chai;
const provider = ethers.provider;
const crypto = require('crypto');
const { MerkleTree } = require('merkletreejs');
const BitSet = require('bitset');

var Web3 = require('web3');
var web3 = new Web3(Web3.givenProvider || 'ws://some.local-or-remote.node:8546');
// FIXME: don't use a stable key
const signer = web3.eth.accounts.create();

const getPasswordHashedAndBloomParams = (numPass) => {
  let unhashed = [];
  let hashed = [];
  // first, generate 2x more paswords
  for (let i = 0; i < numPass * 2; i++) {
    let curUnhashed = crypto.randomBytes(16).toString('hex');
    unhashed.push(curUnhashed);
    let curHashed = ethers.BigNumber.from(keccak256(curUnhashed));
    hashed.push(curHashed);
  }
  // then we are going to search for the perfect hash function
  // we will search the space dynamically with a size and a salt.
  // size will dynamically grow 1.1x
  // salt will just be some small number
  // note, the leaf that is sent is always after keccak256, so when
  // we try to guess the perfect hash function we will also need keccak256
  let bitsetSize = numPass;
  let passwords = [];
  while (true) {
    const oldBitsetSize = bitsetSize;
    bitsetSize = parseInt(bitsetSize * 1.1);
    if (oldBitsetSize == bitsetSize) {
      bitsetSize += 1;
    }
    let bs = new BitSet("0".repeat(bitsetSize));
    hashed.map((v, arrayIdx) => {
      let idx = v.mod(bitsetSize);
      if (bs.get(idx) == 0) {
        passwords.push({
          hashed: v,
          unhashed: unhashed[arrayIdx],
          isClaimed: false,
        });
        bs.set(idx, 1);
      }
    });
    if (bs.cardinality() >= numPass) {
      break;
    } else {
      passwords = [];
    }
  }

  // now we will calculate the merkle tree and the corresponding root
  const merkleTree = new MerkleTree(passwords.map(v => v.unhashed), keccak256, { hashLeaves: true, sortPairs: true });
  const root = merkleTree.getHexRoot();
  
  return {passwords, bitsetSize, root};
}

// describe("PullPaymentEnvelope", function () {
//   let owner, addr1, addr2;
//   let unhashed;
//   let bitsetLength;
//   let fakeToken, redEnvelopeERC20;
//   let id = "1234";
// 
//   beforeEach(async () => {
//     const RedEnvelopeERC20 = await ethers.getContractFactory("PullPaymentERC1155Envelopes");
//     [owner, addr1, addr2] = await ethers.getSigners();
//     redEnvelopeERC20= await RedEnvelopeERC20.deploy();
//     await redEnvelopeERC20.deployed();
//     await redEnvelopeERC20.setSigner(signer.address);
// 
//     // also deploy a fake ERC20 token 
//     // argument is initial supply
//     const FakeToken = await ethers.getContractFactory("FakeToken");
//     [owner, addr1, addr2] = await ethers.getSigners();
//     fakeToken = await FakeToken.deploy(ethers.BigNumber.from(1000));
//     await fakeToken.deployed();
//   });
// 
//   it("Assigns initial balance", async () => {
//     expect(await fakeToken.balanceOf(owner.address)).to.equal(1000)
//   });
//   
//   it("add envelope", async () => {
//     const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
//     hashed = passwords.map(v => v.hashed);
//     unhashed = passwords.map(v => v.unhashed);
//     
//     // first approve, NOTE it is the contract receiving, not the owner
//     const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
//     tx1.wait();
//     expect(await redEnvelopeERC20.upsertEnvelope(id, fakeToken.address, 100, root, bitsetSize, {from: owner.address}));
//   });
// 
//   it("add envelope then open", async () => {
//     const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
//     hashed = passwords.map(v => v.hashed);
//     unhashed = passwords.map(v => v.unhashed);
// 
//     const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
//     const leaf = keccak256(unhashed[0]);
//     const proof = merkleTree.getHexProof(leaf);
//     const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
//     const signed = signer.sign(TEST_MESSAGE);
// 
//     // first approve, NOTE it is the contract receiving, not the owner
//     const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
//     tx1.wait();
//     const tx2 = await redEnvelopeERC20.upsertEnvelope(id, fakeToken.address, 100, root, bitsetSize, {from: owner.address});
//     tx2.wait();
// 
//     expect(await fakeToken.balanceOf(addr1.address)).to.equal(0)
// 
//     const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed.signature, id, proof, leaf, {from: addr1.address});
//     tx.wait();
//     expect(await fakeToken.balanceOf(addr1.address)).to.equal(100)
//   });
// 
//   it("try unapproved token", async () => {
//     const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
//     hashed = passwords.map(v => v.hashed);
//     unhashed = passwords.map(v => v.unhashed);
// 
//     const FakeToken2 = await ethers.getContractFactory("FakeToken");
//     [owner, addr1, addr2] = await ethers.getSigners();
//     fakeToken2 = await FakeToken2.deploy(ethers.BigNumber.from(1000));
//     await fakeToken2.deployed();
//   });
// 
//   it("Two opener", async function () {
//     async function testTwoOpener(minPerOpen, envBalance) {
//       const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(2);
//       hashed = passwords.map(v => v.hashed);
//       unhashed = passwords.map(v => v.unhashed);
//       const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
// 
// 
//       const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
//       tx1.wait();
//       expect(await redEnvelopeERC20.upsertEnvelope(id, fakeToken.address, envBalance, root, bitsetSize, {from: owner.address}));
// 
//       let oldBalance = await fakeToken.balanceOf(addr1.address);
//       let oldBalance2 = await fakeToken.balanceOf(addr2.address);
// 
//       const leaf1 = keccak256(unhashed[0]);
//       const proof1 = merkleTree.getHexProof(leaf1);
//       const leaf2 = keccak256(unhashed[1]);
//       const proof2 = merkleTree.getHexProof(leaf2);
//       const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf1]));
//       const signed1 = signer.sign(TEST_MESSAGE1);
//       const TEST_MESSAGE2 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr2.address, leaf2]));
//       const signed2 = signer.sign(TEST_MESSAGE2);
// 
//       const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, id, proof1, leaf1, {from: addr1.address});
//       const tx2 = await redEnvelopeERC20.connect(addr2).openEnvelope(signed2.signature, id, proof2, leaf2, {from: addr2.address});
//       await tx.wait();
//       await tx2.wait();
//       let newBalance = await fakeToken.balanceOf(addr1.address);
//       let newBalance2 = await fakeToken.balanceOf(addr2.address);
// 
//       expect(newBalance.add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(envBalance));
//       expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
//       expect(newBalance2.sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
//     }
// 
//     let minPerOpen = 200;
//     const envBalance = 500;
//     await testTwoOpener(minPerOpen, envBalance);
//     minPerOpen = 250;
//     await testTwoOpener(minPerOpen, envBalance);
//   });
// 
//   it("Two opener, one open and one returned", async function () {
//     async function testTwoOpener(minPerOpen, envBalance) {
//       const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(2);
//       hashed = passwords.map(v => v.hashed);
//       unhashed = passwords.map(v => v.unhashed);
//       const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
//       const leaf = keccak256(unhashed[0]);
//       const proof = merkleTree.getHexProof(leaf);
// 
//       const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
//       tx1.wait();
//       expect(await redEnvelopeERC20.upsertEnvelope(id, fakeToken.address, envBalance, root, bitsetSize, {from: owner.address}));
// 
//       let oldBalance = await fakeToken.balanceOf(addr1.address);
//       let oldBalance2 = await fakeToken.balanceOf(owner.address);
// 
//       const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
//       const signed1 = signer.sign(TEST_MESSAGE1);
// 
//       const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, id, proof, leaf, {from: addr1.address});
//       const tx2 = await redEnvelopeERC20.returnEnvelope(id);
//       tx.wait();
//       tx2.wait();
//       let newBalance = await fakeToken.balanceOf(addr1.address);
//       let newBalance2 = await fakeToken.balanceOf(owner.address);
// 
//       expect(newBalance.add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(envBalance));
//       expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
//       expect(newBalance2.sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
//     }
// 
//     let minPerOpen = 200;
//     const envBalance = 500;
// 
//     await testTwoOpener(minPerOpen, envBalance);
//   });
// });