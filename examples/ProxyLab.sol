// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// EIP-1967 transparent proxy + a diamond-ish facade, deployed to anvil so the
// resolver has real targets to follow.
contract Impl {
    uint256 public val;
    address public owner;
    constructor() { owner = msg.sender; }
    function setVal(uint256 v) external { val = v; }
    function pwn() external { val = 999; }
}

contract EIP1967Proxy {
    bytes32 internal constant _IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    constructor(address impl) {
        bytes32 s = _IMPL_SLOT;
        assembly { sstore(s, impl) }
    }
    fallback() external {
        address impl;
        bytes32 s = _IMPL_SLOT;
        assembly { impl := sload(s) }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// minimal EIP-1167 clone factory
contract CloneFactory {
    function clone(address impl) external returns (address a) {
        bytes memory m = abi.encodePacked(
            hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"
        );
        bytes32 salt;
        assembly {
            a := create2(0, add(m, 32), mload(m), salt)
        }
    }
}
