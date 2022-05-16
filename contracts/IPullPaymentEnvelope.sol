// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "./IEnvelope.sol";

contract IPullPaymentEnvelope is IEnvelope {
  
  using Bits for uint8;

  struct PullPaymentEnvelope {
    uint256 balance;
    // we need a Merkle roots, to
    // keep track of claimed passwords,
    bytes32 unclaimedPasswordsAndAmount;
    // we will keep a bitset for used passwords
    uint8[] isPasswordClaimed;
    address creator;
    bool isPaused;
  }

  function initEnv(
    PullPaymentEnvelope storage envelope,
    bytes32 hashedMerkelRoot,
    uint32 bitarraySize
  ) internal {
    envelope.creator = msg.sender;
    envelope.isPaused = false;
    envelope.unclaimedPasswordsAndAmount = hashedMerkelRoot;
    envelope.isPasswordClaimed = new uint8[](bitarraySize / 8 + 1);
  }
}