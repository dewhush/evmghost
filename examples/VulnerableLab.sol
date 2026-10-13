// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableLab
/// @notice A deliberately broken contract used to reproduce evmghost's
///         exploit replays locally. Three planted bugs, one false-positive
///         trap. Deploy this to an anvil node and point evmghost at it.
///
/// @dev Bugs planted:
///        - kill()       callable by anyone (missing access control)
///        - mint()       callable by anyone, mints to any address
///        - transferFrom missing the allowance check
///      The false-positive trap is withdraw(), which guards on tx.origin —
///      evmghost must report it as reverting for a stranger, not exploitable.
contract VulnerableLab {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed to, uint256 value);

    constructor() {
        owner = tx.origin;
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = 1_000_000e18;
    }

    /// @dev BUG 1: no access control. Anyone can self-destruct the contract
    ///      and send the balance to themselves.
    function kill() external {
        selfdestruct(payable(msg.sender));
    }

    /// @dev BUG 2: no access control. Anyone can mint to any address.
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Mint(to, amount);
    }

    /// @dev BUG 3: the allowance is never checked nor decremented.
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    /// @dev FALSE-POSITIVE TRAP: guarded on tx.origin. evmghost replays this
    ///      as a stranger and must observe REVERT, not a storage write.
    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "not owner");
        (bool ok, ) = owner.call{value: amount}("");
        require(ok, "send failed");
    }

    /// @dev A normal permissionless read; must not be flagged as a write.
    function paused() external pure returns (bool) {
        return false;
    }
}
