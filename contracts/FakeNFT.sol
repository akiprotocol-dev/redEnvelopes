// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract FakeNFT is ERC721, Ownable {
    constructor() ERC721("FakeNFT", "MTK") {}

    function _baseURI() internal pure override returns (string memory) {
        return "https://fakenft.com/";
    }

    function safeMint(address to, uint256 tokenId) public onlyOwner {
        _safeMint(to, tokenId);
    }
}