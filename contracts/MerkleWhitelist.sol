//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MerkleWhitelist is Ownable {
  bytes32 public wlMerkleRoot;
  bytes32 public ogMerkleRoot;

  string public whitelistURI;

  /*
  READ FUNCTIONS
  */

  //Frontend verify functions
  function verifyWLSender(address userAddress, bytes32[] memory proof) public view returns (bool) {
    return _verify(proof, _hash(userAddress), wlMerkleRoot);
  }

  function verifyOGSender(address userAddress, bytes32[] memory proof) public view returns (bool) {
    return _verify(proof, _hash(userAddress), ogMerkleRoot);
  }

  //Internal verify functions
  function _verifyWLSender(bytes32[] memory proof) internal view returns (bool) {
    return _verify(proof, _hash(msg.sender), wlMerkleRoot);
  }

  function _verifyOGSender(bytes32[] memory proof) internal view returns (bool) {
    return _verify(proof, _hash(msg.sender), ogMerkleRoot);
  }

  function _verify(bytes32[] memory proof, bytes32 addressHash, bytes32 whitelistMerkleRoot)
    internal
    pure
    returns (bool)
  {
    return MerkleProof.verify(proof, whitelistMerkleRoot, addressHash);
  }

  function _hash(address _address) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked(_address));
  }

  /*
  OWNER FUNCTIONS
  */

  function setWLMerkleRoot(bytes32 merkleRoot) external onlyOwner {
    wlMerkleRoot = merkleRoot;
  }

  function setOGMerkleRoot(bytes32 merkleRoot) external onlyOwner {
    ogMerkleRoot = merkleRoot;
  }

  /*
  MODIFIER
  */
  modifier onlyOG(bytes32[] memory proof) {
    require(_verifyOGSender(proof), "MerkleWhitelist: Caller is not whitelisted");
    _;
  }
  
  modifier onlyWL(bytes32[] memory proof) {
    require(_verifyWLSender(proof), "MerkleWhitelist: Caller is not whitelisted");
    _;
  }
}