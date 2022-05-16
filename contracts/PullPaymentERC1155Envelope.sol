
// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "./IPullPaymentEnvelope.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";


contract PullPaymentERC1155Envelopes is IPullPaymentEnvelope, IERC1155Receiver, ERC165 {
  
  using Bits for uint8;

  struct PullPaymentERC1155Envelope {
    PullPaymentEnvelope env;
    IERC1155 token;
    uint256[] ids;
    uint256[] amount;
  }

  mapping(string => PullPaymentERC1155Envelope) private idToEnvelopes;

  function insertEnvelope(
    string calldata envelopeID,
    address tokenAddr,
    uint256[] calldata ids,
    uint256[] calldata amount,
    bytes32 hashedMerkelRoot,
    uint32 bitarraySize
  ) public nonReentrant onlyOwner {
    require(ids.length > 0, "Trying to create zero balance envelope");
    // First try to transfer the ERC20 token
    IERC1155 token = IERC1155(tokenAddr);
    bytes memory data = "";
    token.safeBatchTransferFrom(msg.sender, address(this), ids, amount, data);

    PullPaymentERC1155Envelope storage envelope = idToEnvelopes[envelopeID];
    initEnv(envelope.env, hashedMerkelRoot, bitarraySize);
    envelope.token = token;
    envelope.ids = ids;
    envelope.amount = amount;
  }

  function reclaimEnvelope(
    string calldata envelopeID
  ) public nonReentrant onlyOwner {
    PullPaymentERC1155Envelope storage envelope = idToEnvelopes[envelopeID];
    IERC1155 token = IERC1155(envelope.token);
    bytes memory data = "";
    token.safeBatchTransferFrom(address(this), msg.sender, envelope.ids, envelope.amount, data);
    delete idToEnvelopes[envelopeID];
  }

  function openEnvelope(
      bytes calldata signature,
      string calldata envelopeID,
      bytes32[] calldata proof,
      bytes32 leaf,
      uint256 id
  ) public nonReentrant {
    require(
        idToEnvelopes[envelopeID].amount.length > 0,
        "Envelope cannot be empty"
    );
    require(recover(signature, leaf), "signature does not seem to be provided by signer");
    PullPaymentERC1155Envelope storage currentEnv = idToEnvelopes[envelopeID];

    // First check if the password has been claimed
    uint256 bitarrayLen = currentEnv.env.isPasswordClaimed.length;
    uint32 idx = uint32(uint256(leaf) % bitarrayLen);
    uint32 bitsetIdx = idx / 8;
    uint8 positionInBitset = uint8(idx % 8);
    uint8 curBitSet = currentEnv.env.isPasswordClaimed[bitsetIdx];
    require(curBitSet.bit(positionInBitset) == 0, "password already used!");

    // Now check if it is a valid password
    bool isUnclaimed = MerkleProof.verify(
        proof,
        currentEnv.env.unclaimedPasswordsAndAmount,
        keccak256(abi.encode(msg.sender, id, leaf))
    );
    require(isUnclaimed, "password need to be valid!");

    // claim the password
    currentEnv.env.isPasswordClaimed[bitsetIdx].setBit(positionInBitset);
  }

  // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC1155/IERC1155Receiver.sol
  function onERC1155Received(
    address operator,
    address from,
    uint256 id,
    uint256 value,
    bytes calldata data
  ) external override returns (bytes4) {
    return 0xf23a6e61;
  }

  function onERC1155BatchReceived(
    address operator,
    address from,
    uint256[] calldata ids,
    uint256[] calldata values,
    bytes calldata data
  ) external override returns (bytes4) {
    return 0xbc197c81;
  }


}