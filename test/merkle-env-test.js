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

describe('PasswordGenerator', function (accounts) {
  let hashed;
  let unhashed;
  let bitsetLength;
  beforeEach(async () => {
    let result = getPasswordHashedAndBloomParams(1000);
    let {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1000);

    unhashed = passwords.map(v => v.unhashed);
    hashed = passwords.map(v => v.hashed);
    bitsetLength = bitsetSize;
  });

  it("test hashes map", async function () {
    expect(hashed.length).to.equal(unhashed.length);
    
    let bs = new BitSet("0".repeat(bitsetLength));
    for (var i = 0; i < hashed.length; i++) {
      expect(hashed[i]).to.equal(ethers.BigNumber.from(keccak256(unhashed[i])));
      let idx = hashed[i].mod(bitsetLength);
      // ensure no collision
      expect(bs.get(idx) == 0);
      bs.set(idx);
    }
  });
});

describe("RedEnvelopeZkERC20ChainLink", function () {
  let owner, addr1, addr2;
  let unhashed;
  let bitsetLength;
  let fakeToken, redEnvelopeERC20;
  let id = "1234";

  beforeEach(async () => {
    const RedEnvelopeChainLink = await ethers.getContractFactory("RedEnvelopeZkERC20ChainLink");
    const MockVRFCoordinator = await ethers.getContractFactory("MockVRFCoordinator");
    mockCoordinator = await MockVRFCoordinator.deploy();
    await mockCoordinator.deployed();
    
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelopeERC20 = await RedEnvelopeChainLink.deploy(mockCoordinator.address, 0);
    await redEnvelopeERC20.deployed();
    await redEnvelopeERC20.setSigner(signer.address);

    // also deploy a fake ERC20 token 
    // argument is initial supply
    const FakeToken = await ethers.getContractFactory("FakeToken");
    [owner, addr1, addr2] = await ethers.getSigners();
    fakeToken = await FakeToken.deploy(ethers.BigNumber.from(1000));
    await fakeToken.deployed();
    let tx3 = await redEnvelopeERC20.approveToken(fakeToken.address);
    tx3.wait();
  });

  it("Assigns initial balance", async () => {
    expect(await fakeToken.balanceOf(owner.address)).to.equal(1000)
  });

  it("add envelope", async () => {
    const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);
    
    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    expect(await redEnvelopeERC20.addEnvelope(id, fakeToken.address, 100, 1, 0, root, bitsetSize, {from: owner.address}));
  });

  it("add envelope then open", async () => {
    const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const leaf = keccak256(unhashed[0]);
    const proof = merkleTree.getHexProof(leaf);
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
    const signed = signer.sign(TEST_MESSAGE);

    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    const tx2 = await redEnvelopeERC20.addEnvelope(id, fakeToken.address, 100, 1, 0, root, bitsetSize, {from: owner.address});
    tx2.wait();

    expect(await fakeToken.balanceOf(addr1.address)).to.equal(0)

    const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed.signature, id, proof, leaf, {from: addr1.address});
    tx.wait();
    expect(await fakeToken.balanceOf(addr1.address)).to.equal(100)
  });

  it("Two opener, one open and one returned", async function () {
    async function testTwoOpener(minPerOpen, envBalance) {
      const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(2);
      hashed = passwords.map(v => v.hashed);
      unhashed = passwords.map(v => v.unhashed);
      const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
      const leaf = keccak256(unhashed[0]);
      const proof = merkleTree.getHexProof(leaf);

      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(id, fakeToken.address, envBalance, 2, minPerOpen, root, bitsetSize, {from: owner.address}));

      let oldBalance = await fakeToken.balanceOf(addr1.address);
      let oldBalance2 = await fakeToken.balanceOf(owner.address);

      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
      const signed1 = signer.sign(TEST_MESSAGE1);

      const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, id, proof, leaf, {from: addr1.address});
      tx.wait();

      // try to return envelope right now, but will not be successful
      let shouldReturn = await redEnvelopeERC20.checkUpkeep(signed1.signature);
      expect(shouldReturn[0]).to.be.false;
      console.log('show should return', shouldReturn);
      await provider.send("evm_increaseTime", [30 * 86400 + 1])
      const txUseless = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      txUseless.wait();

      const shouldReturn2 = await redEnvelopeERC20.checkUpkeep(signed1.signature);
      console.log('show new should return', shouldReturn2);
      expect(shouldReturn2[0]).to.be.true;
      const tx2 = await redEnvelopeERC20.performUpkeep(shouldReturn2[1]);
      tx2.wait();

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

});
  

describe("RedEnvelopeERC", function () {
  let owner, addr1, addr2;
  let unhashed;
  let bitsetLength;
  let fakeToken, redEnvelopeERC20;
  let id = "1234";

  beforeEach(async () => {
    const RedEnvelopeERC20 = await ethers.getContractFactory("RedEnvelopeMerkleERC20");
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelopeERC20= await RedEnvelopeERC20.deploy();
    await redEnvelopeERC20.deployed();
    await redEnvelopeERC20.setSigner(signer.address);

    // also deploy a fake ERC20 token 
    // argument is initial supply
    const FakeToken = await ethers.getContractFactory("FakeToken");
    [owner, addr1, addr2] = await ethers.getSigners();
    fakeToken = await FakeToken.deploy(ethers.BigNumber.from(1000));
    await fakeToken.deployed();
    let tx3 = await redEnvelopeERC20.approveToken(fakeToken.address);
    tx3.wait();
  });

  it("Assigns initial balance", async () => {
    expect(await fakeToken.balanceOf(owner.address)).to.equal(1000)
  });
  
  it("add envelope", async () => {
    const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);
    
    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    expect(await redEnvelopeERC20.addEnvelope(id, fakeToken.address, 100, 1, 0, root, bitsetSize, {from: owner.address}));
  });

  it("add envelope then open", async () => {
    const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const leaf = keccak256(unhashed[0]);
    const proof = merkleTree.getHexProof(leaf);
    const TEST_MESSAGE = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
    const signed = signer.sign(TEST_MESSAGE);

    // first approve, NOTE it is the contract receiving, not the owner
    const tx1 = await fakeToken.approve(redEnvelopeERC20.address, 100);
    tx1.wait();
    const tx2 = await redEnvelopeERC20.addEnvelope(id, fakeToken.address, 100, 1, 0, root, bitsetSize, {from: owner.address});
    tx2.wait();

    expect(await fakeToken.balanceOf(addr1.address)).to.equal(0)

    const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed.signature, id, proof, leaf, {from: addr1.address});
    tx.wait();
    expect(await fakeToken.balanceOf(addr1.address)).to.equal(100)
  });

  it("try unapproved token", async () => {
    const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);

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
      const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(2);
      hashed = passwords.map(v => v.hashed);
      unhashed = passwords.map(v => v.unhashed);
      const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });


      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(id, fakeToken.address, envBalance, 2, minPerOpen, root, bitsetSize, {from: owner.address}));

      let oldBalance = await fakeToken.balanceOf(addr1.address);
      let oldBalance2 = await fakeToken.balanceOf(addr2.address);

      const leaf1 = keccak256(unhashed[0]);
      const proof1 = merkleTree.getHexProof(leaf1);
      const leaf2 = keccak256(unhashed[1]);
      const proof2 = merkleTree.getHexProof(leaf2);
      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf1]));
      const signed1 = signer.sign(TEST_MESSAGE1);
      const TEST_MESSAGE2 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr2.address, leaf2]));
      const signed2 = signer.sign(TEST_MESSAGE2);

      const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, id, proof1, leaf1, {from: addr1.address});
      const tx2 = await redEnvelopeERC20.connect(addr2).openEnvelope(signed2.signature, id, proof2, leaf2, {from: addr2.address});
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
      const {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(2);
      hashed = passwords.map(v => v.hashed);
      unhashed = passwords.map(v => v.unhashed);
      const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
      const leaf = keccak256(unhashed[0]);
      const proof = merkleTree.getHexProof(leaf);

      const tx1 = await fakeToken.approve(redEnvelopeERC20.address, envBalance);
      tx1.wait();
      expect(await redEnvelopeERC20.addEnvelope(id, fakeToken.address, envBalance, 2, minPerOpen, root, bitsetSize, {from: owner.address}));

      let oldBalance = await fakeToken.balanceOf(addr1.address);
      let oldBalance2 = await fakeToken.balanceOf(owner.address);

      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
      const signed1 = signer.sign(TEST_MESSAGE1);

      const tx = await redEnvelopeERC20.connect(addr1).openEnvelope(signed1.signature, id, proof, leaf, {from: addr1.address});
      const tx2 = await redEnvelopeERC20.returnEnvelope(id);
      tx.wait();
      tx2.wait();
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
});


describe('RedEnvelopeMerkleERC721', function (accounts) {
  let redEnvelope;
  let addr1, addr2;
  let hashed;
  let unhashed;
  let bitsetLength;
  let fakeNFT;
  const idRange = 30;

  beforeEach(async () => {
    // also deploy the test NFT contract
    const FakeNFT = await ethers.getContractFactory("FakeNFT");
    [owner, addr1, addr2] = await ethers.getSigners();
    fakeNFT = await FakeNFT.deploy();
    await fakeNFT.deployed();
    for (var i = 0 ; i < idRange; i++) {
      fakeNFT.safeMint(owner.address, i);
    }

    const RedEnvelope = await ethers.getContractFactory("RedEnvelopeMerkleERC721");
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelope = await RedEnvelope.deploy();
    await redEnvelope.deployed();
    await redEnvelope.setSigner(signer.address);

    const {passwords, bitsetSize, root}= getPasswordHashedAndBloomParams(idRange);
    hashed = passwords.map(v => v.hashed);
    unhashed = passwords.map(v => v.unhashed);
    bitsetLength = bitsetSize;
  });

  it("create envelope", async function () {
    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const root = merkleTree.getHexRoot();
    const id = "1";
    
    // first approve
    const ids = [1];
    const tx = await fakeNFT.approve(redEnvelope.address, ids[0]);
    await tx.wait();
    expect(await redEnvelope.addEnvelope(id, root, bitsetLength, fakeNFT.address, ids));
  });

  it("one opener", async function () {

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const root = merkleTree.getHexRoot();
    const id = "1";
    const leaf = keccak256(unhashed[0]);
    const proof = merkleTree.getHexProof(leaf);
    
    // first approve
    const ids = [1];
    // at this point, owner still own the nft
    expect(await fakeNFT.ownerOf(ids[0])).to.equal(owner.address);
    const tx = await fakeNFT.setApprovalForAll(redEnvelope.address, true);
    await tx.wait();
    const tx2 = await redEnvelope.addEnvelope(id, root, bitsetLength, fakeNFT.address, ids);
    tx2.wait();
    // now contract owns the NFT
    expect(await fakeNFT.ownerOf(ids[0])).to.equal(redEnvelope.address);

    const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
    const signed1 = signer.sign(TEST_MESSAGE1);
    const tx3 = await redEnvelope.connect(addr1).openEnvelope(signed1.signature, id, proof, leaf, {from: addr1.address});
    await tx3.wait();
    let ownerOf0 = await fakeNFT.ownerOf(ids[0]);
    expect(ownerOf0).to.equal(addr1.address);
  });

  it("N opener", async function () {

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const root = merkleTree.getHexRoot();
    const id = "1";
    
    // first approve
    const ids = [...Array(idRange).keys()];
    const tx = await fakeNFT.setApprovalForAll(redEnvelope.address, true);
    await tx.wait();
    const tx2 = await redEnvelope.addEnvelope(id, root, bitsetLength, fakeNFT.address, ids);
    tx2.wait();
    console.log('show all ids', ids);

    // First make sure the contract owns all the nfts now
    for (const nftID of ids) {
      let ownerOf0 = await fakeNFT.ownerOf(nftID);
      expect(ownerOf0).to.equal(redEnvelope.address);
    }

    for (const nftID of ids) {
      const leaf = keccak256(unhashed[nftID]);
      const proof = merkleTree.getHexProof(leaf);
      const TEST_MESSAGE1 = web3.utils.sha3(web3.eth.abi.encodeParameters(['address', 'bytes32'], [addr1.address, leaf]));
      const signed1 = signer.sign(TEST_MESSAGE1);
      const tx3 = await redEnvelope.connect(addr1).openEnvelope(signed1.signature, id, proof, leaf, {from: addr1.address});
      await tx3.wait();
    }
    for (const nftID of ids) {
      let ownerOf0 = await fakeNFT.ownerOf(nftID);
      expect(ownerOf0).to.equal(addr1.address);
    }
  });

});



describe('RedEnvelopeMerkle', function (accounts) {
  let redEnvelope;
  let addr1, addr2;
  let passwords;
  let unhashed;
  let bitsetLength;
  let rootHex;

  beforeEach(async () => {
    const RedEnvelope = await ethers.getContractFactory("RedEnvelopeMerkle");
    [owner, addr1, addr2] = await ethers.getSigners();
    redEnvelope = await RedEnvelope.deploy();
    await redEnvelope.deployed();

    let {passwords, bitsetSize, root} = getPasswordHashedAndBloomParams(1000);
    bitsetLength = bitsetSize;
    rootHex = root;
    unhashed = passwords.map(v => v.unhashed);

  });

  it("One opener", async function () {

    const id = "1";

    expect(await redEnvelope.addEnvelope(id, 1, 0, rootHex, bitsetLength, {from: owner.address, value: 5000}));

    // need to open envelope with a proof
    const leaf = keccak256(unhashed[0]);
    // this leaf should fail
    // const leaf = keccak256('hello there');
    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const proof = merkleTree.getHexProof(leaf);
    let oldBalance = await provider.getBalance(addr1.address);
    const tx = await redEnvelope.openEnvelope(addr1.address, id, proof, leaf);
    tx.wait();
    let newBalance = await provider.getBalance(addr1.address);
    expect(newBalance.sub(oldBalance)).to.equal(ethers.BigNumber.from(5000));
    
    // when we try to open again, this should fail, because envelope is now empty
    // const tx2 = await redEnvelope.openEnvelope(addr1.address, 1, proof, leaf);
    // tx2.wait();
    // await expect(response.wait()).to.be.reverted;
  });

  it("Two opener", async function () {

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    const id = "1";
    const minPerOpen = 2000;

    expect(await redEnvelope.addEnvelope(id, 2, minPerOpen, rootHex, bitsetLength, {from: owner.address, value: 5000}));

    // need to open envelope with a proof
    const leaf = keccak256(unhashed[0]);
    const leaf2 = keccak256(unhashed[1]);
    // this leaf should fail
    // const leaf = keccak256('hello there');
    const proof = merkleTree.getHexProof(leaf);
    const proof2 = merkleTree.getHexProof(leaf2);

    let oldBalance = await provider.getBalance(addr1.address);
    let oldBalance2 = await provider.getBalance(addr2.address);
    const tx = await redEnvelope.openEnvelope(addr1.address, id, proof, leaf);
    const tx2 = await redEnvelope.openEnvelope(addr2.address, id, proof2, leaf2);
    tx.wait();
    tx2.wait();
    let newBalance = await provider.getBalance(addr1.address);
    let newBalance2 = await provider.getBalance(addr2.address);
    
    expect(newBalance.add(newBalance2).sub(oldBalance).sub(oldBalance2)).to.equal(ethers.BigNumber.from(5000));
    expect(newBalance.sub(oldBalance).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
    expect(newBalance2.sub(oldBalance2).gte(ethers.BigNumber.from(minPerOpen))).to.be.true;

    // when we try to open again, this should fail, because envelope is now empty
    // const tx3 = await redEnvelope.openEnvelope(addr1.address, 1, proof, leaf);
    // await expect(tx3.wait()).to.be.reverted;
  });

  it("1k opener", async function () {

    const id = "1";
    const minPerOpen = 2000;
    const totalVal = ethers.BigNumber.from(minPerOpen * 2000);

    expect(await redEnvelope.addEnvelope(id, 1000, minPerOpen, rootHex, bitsetLength, {from: owner.address, value: totalVal}));

    const merkleTree = new MerkleTree(unhashed, keccak256, { hashLeaves: true, sortPairs: true });
    for (var i = 0; i < 1000; i++) {
      // need to open envelope with a proof
      const leaf = keccak256(unhashed[i]);
      const proof = merkleTree.getHexProof(leaf);
      let oldBalance = await provider.getBalance(addr1.address);
      const tx = await redEnvelope.openEnvelope(addr1.address, id, proof, leaf);
      tx.wait();
      let newBalance = await provider.getBalance(addr1.address);
      const maxPerOpen = totalVal.div(1000).mul(2);
      const thisOpen = newBalance.sub(oldBalance);

      expect(thisOpen.gte(ethers.BigNumber.from(minPerOpen))).to.be.true;
      // incorrect max per open for the very last few envelopes.
      if (i < 995) {
        expect(thisOpen.lte(ethers.BigNumber.from(maxPerOpen))).to.be.true;
      }
    }
  });
});
