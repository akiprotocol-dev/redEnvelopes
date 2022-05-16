// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./IEnvelope.sol";

contract RedEnvelopeERC20String is Ownable, IEnvelope {

    // sigh https://github.com/ethereum/aleth/issues/1788
    struct ERC20Envelope {
        Envelope env;
        IERC20 token;
    }

    mapping(string => ERC20Envelope) private idToEnvelopes;
    mapping(address => bool) public approvedTokens;

    function returnEnvelope(string memory envelopeID) public onlyOwner {
        ERC20Envelope storage envERC20 = idToEnvelopes[envelopeID];
        require(envERC20.env.balance > 0, "balance cannot be zero");
        address payable receiver = payable(envERC20.env.creator);
        IERC20 token = IERC20(envERC20.token);
        SafeERC20.safeApprove(token, address(this), envERC20.env.balance);
        SafeERC20.safeTransferFrom(token, address(this), receiver, envERC20.env.balance);
    }

    function approveToken(address token) public onlyOwner {
        approvedTokens[token] = true;
    }

    function addEnvelope(string memory envelopeID, address tokenAddr, uint256 value, uint16 numParticipants, uint8 passLength, uint256 minPerOpen, uint64[] memory hashedPassword) payable public {
        require(idToEnvelopes[envelopeID].env.balance == 0, "balance not zero");
        require(value > 0, "Trying to create zero balance envelope");
        require(approvedTokens[tokenAddr] == true, "We only allow certain tokens!");
        validateMinPerOpen(value, minPerOpen, numParticipants);

        // First try to transfer the ERC20 token
        IERC20 token = IERC20(tokenAddr);
        SafeERC20.safeTransferFrom(token, msg.sender, address(this), value);

        ERC20Envelope storage envelope = idToEnvelopes[envelopeID];
        envelope.env.minPerOpen = minPerOpen;
        envelope.env.numParticipants = numParticipants;
        envelope.env.creator = msg.sender;
        for (uint i=0; i < hashedPassword.length; i++) {
            envelope.env.passwords[hashedPassword[i]] = initStatus();
        }
        envelope.env.balance = value;
        envelope.token = token;
        envelope.env.passLength = passLength;
    }

    function openEnvelope(address payable receiver, string memory envelopeID, string memory unhashedPassword) public {
        require(idToEnvelopes[envelopeID].env.balance > 0, "Envelope is empty");
        uint64 passInt64 = hashPassword(unhashedPassword);
        ERC20Envelope storage currentEnv = idToEnvelopes[envelopeID];

        // validate the envelope
        Status storage passStatus = currentEnv.env.passwords[passInt64];
        require(passStatus.initialized, "Invalid password!");
        require(!passStatus.claimed, "Password is already used");
        require(bytes(unhashedPassword).length == currentEnv.env.passLength, "password is incorrect length");

        // claim the password
        currentEnv.env.passwords[passInt64].claimed = true;

        // currently withdrawl the full balance, turn this into something either true random or psuedorandom
        if (currentEnv.env.numParticipants == 1) {
            SafeERC20.safeApprove(currentEnv.token, address(this), currentEnv.env.balance);
            SafeERC20.safeTransferFrom(currentEnv.token, address(this), receiver, currentEnv.env.balance);
            currentEnv.env.balance = 0;
            return;
        }
        uint256 moneyThisOpen = getMoneyThisOpen(
            receiver,
            currentEnv.env.balance,
            currentEnv.env.minPerOpen,
            currentEnv.env.numParticipants);
        currentEnv.env.numParticipants--;

        SafeERC20.safeApprove(currentEnv.token, address(this), moneyThisOpen);
        SafeERC20.safeTransferFrom(currentEnv.token, address(this), receiver, moneyThisOpen);
        currentEnv.env.balance -= moneyThisOpen;
    }
}