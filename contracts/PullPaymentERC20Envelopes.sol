// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "./IPullPaymentEnvelope.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract PullPaymentERC20Envelopes is IPullPaymentEnvelope {
  
  using Bits for uint8;

  struct PullPaymentERC20Envelope {
    PullPaymentEnvelope env;
    IERC20 token;
    uint256 value;
  }

  mapping(string => PullPaymentERC20Envelope) private idToEnvelopes;

  function insertEnvelope(
    string calldata envelopeID,
    address tokenAddr,
    uint256 value,
    bytes32 hashedMerkelRoot,
    uint32 bitarraySize
  ) public nonReentrant onlyOwner {
    require(value > 0, "Trying to create zero balance envelope");
    // First try to transfer the ERC20 token
    IERC20 token = IERC20(tokenAddr);
    SafeERC20.safeTransferFrom(token, msg.sender, address(this), value);

    PullPaymentERC20Envelope storage envelope = idToEnvelopes[envelopeID];
    initEnv(envelope.env, hashedMerkelRoot, bitarraySize);
    envelope.token = token;
    envelope.value = value;
  }

  function reclaimEnvelope(
    string calldata envelopeID
  ) public nonReentrant onlyOwner {
    PullPaymentERC20Envelope storage envelope = idToEnvelopes[envelopeID];
    SafeERC20.safeTransferFrom(envelope.token, address(this),  msg.sender, envelope.value);
  }

  function pauseEnvelope(
    string calldata envelopeID
  ) public nonReentrant onlyOwner {

    require(
      idToEnvelopes[envelopeID].value > 0,
      "Envelope cannot be empty"
    );
    PullPaymentERC20Envelope storage envelope = idToEnvelopes[envelopeID];
    envelope.env.isPaused = true;
  }

  function withdrawal(
    bytes calldata signature,
    string calldata envelopeID,
    bytes32[] calldata proof,
    uint256 amount,
    bytes32 leaf
  ) public nonReentrant {
      require(
          idToEnvelopes[envelopeID].value > 0,
          "Envelope cannot be empty"
      );
      PullPaymentERC20Envelope storage currentEnv = idToEnvelopes[envelopeID];
      require(currentEnv.env.isPaused, "Envelope has been paused!");
      require(recover(signature, leaf), "signature does not seem to be provided by signer");

      // First check if the password has been claimed
      uint256 bitarrayLen = currentEnv.env.isPasswordClaimed.length;
      uint32 idx = uint32(uint256(leaf) % bitarrayLen);
      uint32 bitsetIdx = idx / 8;
      uint8 positionInBitset = uint8(idx % 8);
      uint8 curBitSet = currentEnv.env.isPasswordClaimed[bitsetIdx];
      require(curBitSet.bit(positionInBitset) == 0, "password already used!");

      // Now check if it is a valid password
      bool validAmountAndSender = MerkleProof.verify(
          proof,
          currentEnv.env.unclaimedPasswordsAndAmount,
          keccak256(abi.encode(msg.sender, leaf, amount))
      );
      require(validAmountAndSender, "password need to be valid!");

      // claim the password
      currentEnv.env.isPasswordClaimed[bitsetIdx].setBit(positionInBitset);

      currentEnv.value -= amount;
      SafeERC20.safeApprove(currentEnv.token, address(this), amount);
      SafeERC20.safeTransferFrom(currentEnv.token, address(this), msg.sender, amount);
  }

}