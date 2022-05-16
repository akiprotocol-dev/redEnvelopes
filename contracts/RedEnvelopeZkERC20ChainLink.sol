// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import "./IEnvelope.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/KeeperCompatible.sol";

contract RedEnvelopeZkERC20ChainLink is IEnvelope, VRFConsumerBaseV2, KeeperCompatibleInterface {

    // Begin VRF section
    // see https://docs.chain.link/docs/vrf-contracts/#configurations
    VRFCoordinatorV2Interface COORDINATOR;
    // Your subscription ID.
    uint64 s_subscriptionId;
    // see https://docs.chain.link/docs/vrf-contracts/#configurations
    bytes32 keyHash = 0xd89b2bf150e3b9e13446986e571fb9cab24b13cea0a43ea20a6049a85cc807cc;
    uint32 callbackGasLimit = 100000;
    uint16 requestConfirmations = 3;
    uint32 numWords =  1;
    uint256 kThirtyDays = 30 * 86400;

    uint256[] public s_randomWords;
    uint256 public s_requestId;
    // End VRF section
    constructor(address vrfCoordinator, uint64 subscriptionId) VRFConsumerBaseV2(vrfCoordinator) {
        COORDINATOR = VRFCoordinatorV2Interface(vrfCoordinator);
        s_subscriptionId = subscriptionId;
    }

    // Assumes the subscription is funded sufficiently.
    function requestRandomWords() internal {
        // Will revert if subscription is not set and funded.
        s_requestId = COORDINATOR.requestRandomWords(
            keyHash,
            s_subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
    }
    
    function fulfillRandomWords(
        uint256, /* requestId */
        uint256[] memory randomWords
    ) internal override {
        s_randomWords = randomWords;
    }

    function getRand(address receiver) internal virtual override returns (uint16) {
        requestRandomWords();
        return uint16(s_randomWords[0]);
    }


    using Bits for uint8;

    struct MerkleERC20Envelope {
        uint256 balance;
        uint256 minPerOpen;
        // we need a Merkle roots, to
        // keep track of claimed passwords,
        bytes32 unclaimedPasswords;
        // we will keep a bitset for used passwords
        uint8[] isPasswordClaimed;
        address creator;
        uint16 numParticipants;
        IERC20 token;
        uint256 createTimestamp;
    }

    mapping(string => MerkleERC20Envelope) private idToEnvelopes;
    string[] private envelopeIDs; 
    mapping(address => bool) public approvedTokens;

    function checkUpkeep(bytes calldata /* checkData */) external view override returns (bool upkeepNeeded, bytes memory performData) {
        upkeepNeeded = false;
        for (uint32 i = 0; i < envelopeIDs.length; i++) {
            string storage envID = envelopeIDs[i];
            if (idToEnvelopes[envID].balance > 0 && block.timestamp - idToEnvelopes[envID].createTimestamp > kThirtyDays) {
                upkeepNeeded = true;
                // FIXME: need to pack the data here
                performData = abi.encode(envID);
                break;
            }
        }
    }
        
    function performUpkeep(bytes calldata performData) external override {
        string memory envID = abi.decode(performData, (string));
        MerkleERC20Envelope memory env = idToEnvelopes[envID];
        if (env.balance > 0 && block.timestamp - env.createTimestamp > kThirtyDays) {
            IERC20 token = IERC20(env.token);
            address receiver = payable(env.creator);
            uint256 oldBalance = env.balance;
            delete idToEnvelopes[envID];
            for (uint32 i = 0; i < envelopeIDs.length; i++) {
                if (compareStrings(envelopeIDs[i], envID)) {
                    _burnStr(envelopeIDs, i);
                    break;
                }
            }
            SafeERC20.safeApprove(token, address(this), oldBalance);
            SafeERC20.safeTransferFrom(token, address(this), receiver, oldBalance);
        }
    }

    function approveToken(address token) public onlyOwner {
        approvedTokens[token] = true;
    }

    function addEnvelope(
        string calldata envelopeID,
        address tokenAddr,
        uint256 value,
        uint16 numParticipants,
        uint256 minPerOpen,
        bytes32 hashedMerkelRoot,
        uint32 bitarraySize
    ) public nonReentrant {
        require(idToEnvelopes[envelopeID].balance == 0, "balance not zero");
        require(value > 0, "Trying to create zero balance envelope");
        require(approvedTokens[tokenAddr] == true, "We only allow certain tokens!");
        validateMinPerOpen(value, minPerOpen, numParticipants);

        // First try to transfer the ERC20 token
        IERC20 token = IERC20(tokenAddr);
        SafeERC20.safeTransferFrom(token, msg.sender, address(this), value);

        MerkleERC20Envelope storage envelope = idToEnvelopes[envelopeID];
        envelope.minPerOpen = minPerOpen;
        envelope.numParticipants = numParticipants;
        envelope.creator = msg.sender;
        envelope.unclaimedPasswords = hashedMerkelRoot;
        envelope.balance = value;
        envelope.isPasswordClaimed = new uint8[](bitarraySize / 8 + 1);
        envelope.token = token;
        envelope.createTimestamp = block.timestamp;
        envelopeIDs.push(envelopeID);
    }

    function openEnvelope(
        bytes calldata signature,
        string calldata envelopeID,
        bytes32[] calldata proof,
        bytes32 leaf
    ) public nonReentrant {
        require(
            idToEnvelopes[envelopeID].balance > 0,
            "Envelope cannot be empty"
        );
        require(recover(signature, leaf), "signature does not seem to be provided by signer");
        MerkleERC20Envelope storage currentEnv = idToEnvelopes[envelopeID];

        // First check if the password has been claimed
        uint256 bitarrayLen = currentEnv.isPasswordClaimed.length;
        uint32 idx = uint32(uint256(leaf) % bitarrayLen);
        uint32 bitsetIdx = idx / 8;
        uint8 positionInBitset = uint8(idx % 8);
        uint8 curBitSet = currentEnv.isPasswordClaimed[bitsetIdx];
        require(curBitSet.bit(positionInBitset) == 0, "password already used!");

        // Now check if it is a valid password
        bool isUnclaimed = MerkleProof.verify(
            proof,
            currentEnv.unclaimedPasswords,
            leaf
        );
        require(isUnclaimed, "password need to be valid!");

        // claim the password
        currentEnv.isPasswordClaimed[bitsetIdx].setBit(positionInBitset);

        // currently withdrawl the full balance, turn this into something either true random or psuedorandom
        if (currentEnv.numParticipants == 1) {
            uint256 oldBalance = currentEnv.balance;
            SafeERC20.safeApprove(currentEnv.token, address(this), oldBalance);
            SafeERC20.safeTransferFrom(currentEnv.token, address(this), msg.sender, oldBalance);
            currentEnv.balance = 0;
            return;
        }

        uint256 moneyThisOpen = getMoneyThisOpen(
            msg.sender,
            currentEnv.balance,
            currentEnv.minPerOpen,
            currentEnv.numParticipants
        );

        currentEnv.numParticipants--;
        currentEnv.balance -= moneyThisOpen;
        SafeERC20.safeApprove(currentEnv.token, address(this), moneyThisOpen);
        SafeERC20.safeTransferFrom(currentEnv.token, address(this), msg.sender, moneyThisOpen);
    }
}
