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
const { soliditySha3, abi} = require("web3-utils");

var Web3 = require('web3');
var web3 = new Web3(Web3.givenProvider || 'ws://some.local-or-remote.node:8546');
const signer = web3.eth.accounts.create();


const getPasswordHashedAndUnhashed = (numPass, passLen) => {
  let unhashed = [];
  let hashed = [];
  for (let i = 0; i < numPass; i++) {
    let curUnhashed = crypto.randomBytes(passLen/2).toString('hex');
    let curHashed = ethers.BigNumber.from(keccak256(curUnhashed)).mod(ethers.BigNumber.from(2).pow(64).sub(1));
    unhashed.push(curUnhashed);
    hashed.push(curHashed);
  }
  return {"hashed": hashed, "unhashed": unhashed};
}

function toEthSignedMessageHash (messageHex) {
  const messageBuffer = Buffer.from(messageHex.substring(2), 'hex');
  const prefix = Buffer.from(`\u0019Ethereum Signed Message:\n${messageBuffer.length}`);
  return web3.utils.sha3(Buffer.concat([prefix, messageBuffer]));
}


describe("RedEnvelope", function () {
  let redEnvelope;
  let unhashedPassword = '123456780';
  let unhashedPassword2 = ['123456789', '910111213']
  let addr1, addr2;

  beforeEach(async () => {
    const RedEnvelope = await ethers.getContractFactory("RedEnvelope");
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelope = await RedEnvelope.deploy();
    await redEnvelope.deployed();
    await redEnvelope.setSigner(signer.address);
  });


  it("One opener", async function () {
    const hashed = await redEnvelope.hashPassword(unhashedPassword);
    let hashes = [hashed];
    expect(await redEnvelope.addEnvelope(1, 1, 9, 0, hashes, {from: owner.address, value: 5000}));

    let oldBalance = await provider.getBalance(addr1.address);
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword]));
    const signed = signer.sign(TEST_MESSAGE);

    const tx = await redEnvelope.connect(addr1).openEnvelope(signed.signature, 1, unhashedPassword, {from: addr1.address});
    const receipt = await tx.wait();
    const totalGasUsed = receipt.cumulativeGasUsed.mul(receipt.effectiveGasPrice);
    let newBalance = await provider.getBalance(addr1.address);
    expect(newBalance.add(totalGasUsed).sub(oldBalance)).to.equal(ethers.BigNumber.from(5000));
    
    // this should fail
    // const response = await redEnvelope.openEnvelope(owner.address, 1, unhashedPassword);
    // await expect(response.wait()).to.be.reverted;
  });

  it("Two opener", async function () {
    const hashes = [];
    for (var i = 0; i < unhashedPassword2.length; i++) {
      let currentHash = await redEnvelope.hashPassword(unhashedPassword2[i]);
      hashes.push(currentHash);
    }
    const minPerOpen = 2000;
    expect(await redEnvelope.addEnvelope(1, 2, 9, minPerOpen, hashes, {from: owner.address, value: 5000}));

    let oldBalance = await provider.getBalance(addr1.address);
    let oldBalance2 = await provider.getBalance(addr2.address);
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword2[0]]));
    const signed1 = signer.sign(TEST_MESSAGE);
    const TEST_MESSAGE2 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr2.address, unhashedPassword2[1]]));
    const signed2 = signer.sign(TEST_MESSAGE2);

    const tx = await redEnvelope.connect(addr1).openEnvelope(signed1.signature, 1, unhashedPassword2[0], {from: addr1.address});
    const tx2 = await redEnvelope.connect(addr2).openEnvelope(signed2.signature, 1, unhashedPassword2[1], {from: addr2.address});
    const receipt1 = await tx.wait();
    const receipt2 = await tx2.wait();
    let newBalance = await provider.getBalance(addr1.address);
    let newBalance2 = await provider.getBalance(addr2.address);
    const totalGasUsed1 = receipt1.cumulativeGasUsed.mul(receipt1.effectiveGasPrice);
    const totalGasUsed2 = receipt2.cumulativeGasUsed.mul(receipt2.effectiveGasPrice);
    expect(newBalance.add(totalGasUsed1).add(totalGasUsed2).add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(5000));
    expect(newBalance.add(totalGasUsed1).sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
    expect(newBalance2.add(totalGasUsed2).sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
  });

  it("Two opener, but only one opened, and rest returned", async function () {
    const hashes = [];
    for (var i = 0; i < unhashedPassword2.length; i++) {
      let currentHash = await redEnvelope.hashPassword(unhashedPassword2[i]);
      hashes.push(currentHash);
    }
    const minPerOpen = 2000;
    expect(await redEnvelope.addEnvelope(1, 2, 9, minPerOpen, hashes, {from: owner.address, value: 5000}));

    let oldBalance = await provider.getBalance(addr1.address);
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword2[0]]));
    const signed1 = signer.sign(TEST_MESSAGE);
    const tx = await redEnvelope.connect(addr1).openEnvelope(signed1.signature, 1, unhashedPassword2[0], {from: addr1.address});
    const receipt2 = await tx.wait();
    let newBalance = await provider.getBalance(addr1.address);
    let oldBalance2 = await provider.getBalance(owner.address);

    // FIXME: without this line, we will fail the timelock
    await provider.send("evm_increaseTime", [86401])

    const tx2 = await redEnvelope.returnEnvelope(1);
    const receipt = await tx2.wait();
    let newBalance2 = await provider.getBalance(owner.address);
    
    // Need to pay attention to gas used because owner is also paying for gas throughout this
    const totalGasUsed = receipt.cumulativeGasUsed.mul(receipt.effectiveGasPrice);
    const totalGasUsed2 = receipt2.cumulativeGasUsed.mul(receipt2.effectiveGasPrice);
    expect(newBalance.add(totalGasUsed).add(totalGasUsed2).add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(5000));
    expect(newBalance.add(totalGasUsed2).sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
  });
});

describe("RedEnvelopeERC", function () {
  let unhashedPassword = '123456780';
  let unhashedPassword2 = ['123456789', '910111213']
  let owner, addr1, addr2;
  let fakeToken, redEnvelopeERC20;

  beforeEach(async () => {
    const RedEnvelopERC20 = await ethers.getContractFactory("RedEnvelopeERC20");
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelopeERC20 = await RedEnvelopERC20.deploy();
    await redEnvelopeERC20.deployed();
    
    // also deploy a fake ERC20 token 
    // argument is initial supply
    const FakeToken = await ethers.getContractFactory("FakeToken");
    [owner, addr1, addr2] = await ethers.getSigners();
    fakeToken = await FakeToken.deploy(ethers.BigNumber.from(1000));
    await fakeToken.deployed();
    let tx3 = await redEnvelopeERC20.approveToken(fakeToken.address);
    await tx3.wait();
    await redEnvelopeERC20.setSigner(signer.address);
  });

  it("Assigns initial balance", async () => {
    expect(await fakeToken.balanceOf(owner.address)).to.equal(1000)
  });

  it("confirm hash", async () => {
    const hashed = await redEnvelopeERC20.hashPassword(unhashedPassword);
    const pureJS = ethers.BigNumber.from(keccak256(unhashedPassword)).mod(ethers.BigNumber.from(2).pow(64).sub(1));
    expect(hashed).to.equal(pureJS);
  });
  
  it("add envelope", async () => {
    const hashed = await redEnvelopeERC20.hashPassword(unhashedPassword);
    let hashes = [hashed];
    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    expect(await redEnvelopeERC20.addEnvelope(1, fakeToken.address, 100, 1, 9, 0, hashes, {from: owner.address}));
  });

  it("add envelope then open", async () => {
    const hashed = await redEnvelopeERC20.hashPassword(unhashedPassword);
    let hashes = [hashed];
    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    tx2 = await redEnvelopeERC20.addEnvelope(1, fakeToken.address, 100, 1, 9, 0, hashes, {from: owner.address});
    tx2.wait();

    expect(await fakeToken.balanceOf(addr1.address)).to.equal(0)
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword]));
    const signed = signer.sign(TEST_MESSAGE);
    const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed.signature, 1, unhashedPassword, {from: addr1.address});
    await tx.wait();
    expect(await fakeToken.balanceOf(addr1.address)).to.equal(100)
  });

  it("try unapproved token", async () => {
    const hashed = await redEnvelopeERC20.hashPassword(unhashedPassword);
    let hashes = [hashed];

    const FakeToken2 = await ethers.getContractFactory("FakeToken");
    [owner, addr1, addr2] = await ethers.getSigners();
    fakeToken2 = await FakeToken2.deploy(ethers.BigNumber.from(1000));
    await fakeToken2.deployed();

    // this should fail since we never approved fakeToken2
    // const tx1 = await fakeToken2.approve(redEnvelopeERC20.address, 100);
    // tx1.wait();
    // tx2 = await redEnvelopeERC20.addEnvelope(1, fakeToken2.address, 100, 1, 9, 0, hashes, {from: owner.address, value: 5000});
    // tx2.wait();
  });

  it("Two opener", async function () {
    async function testTwoOpener(minPerOpen, envBalance) {
      const hashes = [];
      for (var i = 0; i < unhashedPassword2.length; i++) {
        let currentHash = await redEnvelopeERC20.hashPassword(unhashedPassword2[i]);
        hashes.push(currentHash);
      }
      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(1, fakeToken.address, envBalance, 2, 9, minPerOpen, hashes, {from: owner.address}));

      let oldBalance = await fakeToken.balanceOf(addr1.address);
      let oldBalance2 = await fakeToken.balanceOf(addr2.address);
      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword2[0]]));
      const signed1 = signer.sign(TEST_MESSAGE1);
      const TEST_MESSAGE2 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr2.address, unhashedPassword2[1]]));
      const signed2 = signer.sign(TEST_MESSAGE2);
      const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, 1, unhashedPassword2[0], {from: addr1.address});
      const tx2 = await redEnvelopeERC20.connect(addr2).openEnvelope(signed2.signature, 1, unhashedPassword2[1], {from: addr2.address});
      await tx.wait();
      await tx2.wait();
      let newBalance = await fakeToken.balanceOf(addr1.address);
      let newBalance2 = await fakeToken.balanceOf(addr2.address);

      expect(newBalance.add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(envBalance));
      expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
      expect(newBalance2.sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
    }

    let minPerOpen = 200;
    const envBalance = 500;
    await testTwoOpener(minPerOpen, envBalance);
    minPerOpen = 250;
    await testTwoOpener(minPerOpen, envBalance);
  });

  it("Two opener, one open and one returned", async function () {
    async function testTwoOpener(minPerOpen, envBalance) {
      const hashes = [];
      for (var i = 0; i < unhashedPassword2.length; i++) {
        let currentHash = await redEnvelopeERC20.hashPassword(unhashedPassword2[i]);
        hashes.push(currentHash);
      }
      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(1, fakeToken.address, envBalance, 2, 9, minPerOpen, hashes, {from: owner.address}));
      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashedPassword2[0]]));
      const signed1 = signer.sign(TEST_MESSAGE1);

      let oldBalance = await fakeToken.balanceOf(addr1.address);
      let oldBalance2 = await fakeToken.balanceOf(owner.address);
      const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, 1, unhashedPassword2[0], {from: addr1.address});
      await tx.wait();

      await provider.send("evm_increaseTime", [86401])
      const tx2 = await redEnvelopeERC20.returnEnvelope(1);
      await tx2.wait();

      let newBalance = await fakeToken.balanceOf(addr1.address);
      let newBalance2 = await fakeToken.balanceOf(owner.address);

      expect(newBalance.add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(envBalance));
      expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
      expect(newBalance2.sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
    }

    let minPerOpen = 200;
    const envBalance = 500;

    await testTwoOpener(minPerOpen, envBalance);
  });


  it("N opener", async function () {
    async function testNOpener(N, minPerOpen, envBalance) {
      const result = getPasswordHashedAndUnhashed(N, 20);
      const hashes = result["hashed"]
      const unhashed = result["unhashed"];

      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(1, fakeToken.address, envBalance, N, 20, minPerOpen, hashes, {from: owner.address}));

      let total = ethers.BigNumber.from(0);
      for (var i = 0; i < N; i++) {
        let oldBalance = await fakeToken.balanceOf(addr1.address);
        const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'string'], [addr1.address, unhashed[i]]));
        const signed1 = signer.sign(TEST_MESSAGE1);
        const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, 1, unhashed[i]);
        await tx.wait();
        let newBalance = await fakeToken.balanceOf(addr1.address);
        expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
        total = total.add(newBalance).sub(oldBalance);
      }
      expect(total).to.equal(ethers.BigNumber.from(envBalance));
    }

    let minPerOpen = 20;
    const envBalance = 500;
    await testNOpener(10, minPerOpen, envBalance);
  });
});

describe('MerkleProofVerify', function (accounts) {
  beforeEach(async function () {
      // this.merkleProofVerify = await MerkleProofVerify.new();
      const MerkleProofVerify = await ethers.getContractFactory("MerkleProofWrapper");
      [owner, addr1, addr2] = await ethers.getSigners();
      this.merkleProofVerify = await MerkleProofVerify.deploy();
      this.hashes = getPasswordHashedAndUnhashed(1000, 32);
  });

  // it('should return true for a valid leaf', async function () {
  //   // const elements = this.hashes["unhashed"];
  //   const elements = this.hashes["unhashed"];

  //   const merkleTree = new MerkleTree(elements, keccak256, { hashLeaves: true, sortPairs: true });

  //  const root = merkleTree.getHexRoot();
  //  // every single element should show true
  //  for (var i = 0; i < elements.length; i++) {
  //   const leaf = keccak256(elements[0]);
  //   const proof = merkleTree.getHexProof(leaf);
  //   expect(await this.merkleProofVerify.verify(proof, root, leaf)).to.equal(true);
  //  }
  // });

  it('returns false for an invalid Merkle proof', async function () {
    const correctElements = this.hashes["unhashed"];
    const correctMerkleTree = new MerkleTree(correctElements, keccak256, { hashLeaves: true, sortPairs: true });

    const correctRoot = correctMerkleTree.getHexRoot();

    const correctLeaf = keccak256(correctElements[0]);

    const newPasswords = getPasswordHashedAndUnhashed(100, 32);
    const badElements = newPasswords["unhashed"];
    // const badMerkleTree = new MerkleTree(badElements);

    let badProof = correctMerkleTree.getHexProof(badElements[0]);

    // this would fail
    expect(await this.merkleProofVerify.verify(badProof, correctRoot, correctLeaf)).to.equal(false);

    badProof = badProof.slice(0, badProof.length - 5);
    expect(await this.merkleProofVerify.verify(badProof, correctRoot, correctLeaf)).to.equal(false);

  });
});