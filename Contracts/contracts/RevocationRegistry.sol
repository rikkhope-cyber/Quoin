// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Optimized on-chain revocation registry for credentials.
/// @dev Uses bitmap packing to store 256 revocation statuses per storage slot.
///      Supports optional per-token revocation expiry.
contract RevocationRegistry is Ownable {
    // tokenContract => bucketIndex => bitmap
    mapping(address => mapping(uint256 => uint256)) private _revokedBitmap;

    // tokenContract => tokenId => expiry timestamp
    mapping(address => mapping(uint256 => uint256)) public revocationExpiry;

    // tokenContract => tokenId => revocation timestamp
    mapping(address => mapping(uint256 => uint256)) public revocationTimestamp;

    // tokenContract => tokenId => revocation reason
    mapping(address => mapping(uint256 => string)) public revocationReason;

    // Cached count of revoked tokens per contract.
    mapping(address => uint256) public revokedCount;

    event RevocationSet(
        address indexed tokenContract,
        uint256 indexed tokenId,
        bool revoked,
        uint256 expiry
    );

    event RevocationSetWithReason(
        address indexed tokenContract,
        uint256 indexed tokenId,
        bool revoked,
        uint256 expiry,
        uint256 timestamp,
        string reason
    );

    event RevocationBatchSet(
        address indexed tokenContract,
        uint256 indexed fromTokenId,
        uint256 count,
        uint256 expiry
    );

    event RevocationBatchCleared(address indexed tokenContract, uint256 count);

    event RevokerUpdated(address indexed revoker, bool allowed);

    event Revoked(
        address indexed tokenContract,
        uint256 indexed tokenId,
        uint64 timestamp
    );

    /// @dev Addresses allowed to change revocation status.
    mapping(address => bool) public revokers;

    modifier onlyRevoker() {
        require(
            msg.sender == owner() || revokers[msg.sender],
            "not authorized to revoke"
        );
        _;
    }

    /// @dev Grant or revoke permission to write revocation records.
    function setRevoker(address revoker, bool allowed) external onlyOwner {
        revokers[revoker] = allowed;
        emit RevokerUpdated(revoker, allowed);
    }

    // ── Single operations ─────────────────────────────────

    function setRevoked(
        address tokenContract,
        uint256 tokenId,
        bool isTokenRevoked
    ) external onlyRevoker {
        _setRevoked(tokenContract, tokenId, isTokenRevoked, 0, "");
    }

    function setRevokedWithReason(
        address tokenContract,
        uint256 tokenId,
        bool isTokenRevoked,
        string memory reason
    ) external onlyRevoker {
        _setRevoked(tokenContract, tokenId, isTokenRevoked, 0, reason);
    }

    function setRevokedWithExpiry(
        address tokenContract,
        uint256 tokenId,
        bool isTokenRevoked,
        uint256 expiry
    ) external onlyRevoker {
        _setRevoked(tokenContract, tokenId, isTokenRevoked, expiry, "");
    }

    function setRevokedWithExpiryAndReason(
        address tokenContract,
        uint256 tokenId,
        bool isTokenRevoked,
        uint256 expiry,
        string memory reason
    ) external onlyRevoker {
        _setRevoked(tokenContract, tokenId, isTokenRevoked, expiry, reason);
    }

    // ── Batch operations ──────────────────────────────────

    /// @dev Batch set revocation status for multiple tokens.
    function batchSetRevoked(
        address tokenContract,
        uint256[] calldata tokenIds,
        bool[] calldata isTokenRevoked
    ) external onlyRevoker {
        require(
            tokenIds.length == isTokenRevoked.length,
            "array length mismatch"
        );

        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(
                tokenContract,
                tokenIds[i],
                isTokenRevoked[i],
                0,
                ""
            );
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Batch set revocation with individual expiry timestamps.
    function batchSetRevokedWithExpiry(
        address tokenContract,
        uint256[] calldata tokenIds,
        bool[] calldata isTokenRevoked,
        uint256[] calldata expiries
    ) external onlyRevoker {
        require(
            tokenIds.length == isTokenRevoked.length,
            "array length mismatch"
        );
        require(
            tokenIds.length == expiries.length,
            "expiry array length mismatch"
        );

        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(
                tokenContract,
                tokenIds[i],
                isTokenRevoked[i],
                expiries[i],
                ""
            );
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Batch set revocation for a contiguous range.
    function batchSetRevokedInRange(
        address tokenContract,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool isTokenRevoked
    ) external onlyRevoker {
        require(fromTokenId <= toTokenId, "invalid range");

        uint256 count = 0;

        for (uint256 i = fromTokenId; i <= toTokenId; ) {
            _setRevoked(tokenContract, i, isTokenRevoked, 0, "");

            unchecked {
                ++i;
                ++count;
            }
        }

        if (isTokenRevoked) {
            emit RevocationBatchSet(tokenContract, fromTokenId, count, 0);
        }
    }

    /// @dev Batch set revocation for a contiguous range with expiry.
    function batchSetRevokedInRangeWithExpiry(
        address tokenContract,
        uint256 fromTokenId,
        uint256 toTokenId,
        bool isTokenRevoked,
        uint256 expiry
    ) external onlyRevoker {
        require(fromTokenId <= toTokenId, "invalid range");

        uint256 count = 0;

        for (uint256 i = fromTokenId; i <= toTokenId; ) {
            _setRevoked(tokenContract, i, isTokenRevoked, expiry, "");

            unchecked {
                ++i;
                ++count;
            }
        }

        if (isTokenRevoked) {
            emit RevocationBatchSet(
                tokenContract,
                fromTokenId,
                count,
                expiry
            );
        }
    }

    /// @dev Revoke multiple tokens in one transaction.
    function batchRevoke(
        address tokenContract,
        uint256[] calldata tokenIds
    ) external onlyRevoker {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], true, 0, "");

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Revoke multiple tokens with a shared reason.
    function batchRevokeWithReason(
        address tokenContract,
        uint256[] calldata tokenIds,
        string memory reason
    ) external onlyRevoker {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], true, 0, reason);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Unrevoke multiple tokens in one transaction.
    function batchUnrevoke(
        address tokenContract,
        uint256[] calldata tokenIds
    ) external onlyRevoker {
        for (uint256 i = 0; i < tokenIds.length; ) {
            _setRevoked(tokenContract, tokenIds[i], false, 0, "");

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Clear all revocation state for a contract.
    ///      This operation remains restricted to the owner.
    function clearAll(address tokenContract) external onlyOwner {
        uint256 count = revokedCount[tokenContract];

        if (count == 0) return;

        uint256 cleared = 0;
        uint256 bucket = 0;

        while (cleared < count) {
            uint256 current = _revokedBitmap[tokenContract][bucket];

            if (current != 0) {
                _revokedBitmap[tokenContract][bucket] = 0;
                cleared += _countBits(current);
            }

            unchecked {
                ++bucket;
            }
        }

        revokedCount[tokenContract] = 0;

        emit RevocationBatchCleared(tokenContract, count);
    }

    // ── Query functions ───────────────────────────────────

    function isRevoked(
        address tokenContract,
        uint256 tokenId
    ) public view returns (bool) {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;

        bool bitSet =
            ((_revokedBitmap[tokenContract][bucket] >> bit) & 1) == 1;

        if (!bitSet) return false;

        uint256 exp = revocationExpiry[tokenContract][tokenId];

        if (exp != 0 && block.timestamp > exp) {
            return false;
        }

        return true;
    }

    /// @dev Batch check revocation status for multiple tokens.
    function batchIsRevoked(
        address tokenContract,
        uint256[] calldata tokenIds
    ) external view returns (bool[] memory results) {
        results = new bool[](tokenIds.length);

        for (uint256 i = 0; i < tokenIds.length; ) {
            results[i] = isRevoked(tokenContract, tokenIds[i]);

            unchecked {
                ++i;
            }
        }
    }

    function getRevokedBitmap(
        address tokenContract,
        uint256 bucket
    ) external view returns (uint256) {
        return _revokedBitmap[tokenContract][bucket];
    }

    function getRevocationRecord(
        address tokenContract,
        uint256 tokenId
    )
        external
        view
        returns (
            bool active,
            uint256 timestamp,
            string memory reason,
            uint256 expiry
        )
    {
        return (
            isRevoked(tokenContract, tokenId),
            revocationTimestamp[tokenContract][tokenId],
            revocationReason[tokenContract][tokenId],
            revocationExpiry[tokenContract][tokenId]
        );
    }

    // ── Internal functions ────────────────────────────────

    function _setRevoked(
        address tokenContract,
        uint256 tokenId,
        bool isTokenRevoked,
        uint256 expiry,
        string memory reason
    ) private {
        uint256 bucket = tokenId / 256;
        uint256 bit = tokenId % 256;
        uint256 mask = 1 << bit;

        uint256 current = _revokedBitmap[tokenContract][bucket];

        bool bitSet = ((current >> bit) & 1) == 1;

        uint256 storedExpiry = revocationExpiry[tokenContract][tokenId];

        bool currentlyRevoked =
            bitSet &&
            !(storedExpiry != 0 && block.timestamp > storedExpiry);

        if (isTokenRevoked) {
            if (currentlyRevoked) return;

            _revokedBitmap[tokenContract][bucket] = current | mask;

            if (!bitSet) {
                revokedCount[tokenContract]++;
            }

            revocationExpiry[tokenContract][tokenId] = expiry;
            revocationTimestamp[tokenContract][tokenId] = block.timestamp;

            if (bytes(reason).length > 0) {
                revocationReason[tokenContract][tokenId] = reason;
            }

            emit Revoked(
                tokenContract,
                tokenId,
                uint64(block.timestamp)
            );

            emit RevocationSetWithReason(
                tokenContract,
                tokenId,
                true,
                expiry,
                block.timestamp,
                reason
            );
        } else {
            if (!bitSet) return;

            _revokedBitmap[tokenContract][bucket] = current & ~mask;

            revokedCount[tokenContract]--;

            delete revocationExpiry[tokenContract][tokenId];
            delete revocationTimestamp[tokenContract][tokenId];
            delete revocationReason[tokenContract][tokenId];
        }

        emit RevocationSet(
            tokenContract,
            tokenId,
            isTokenRevoked,
            expiry
        );
    }

    /// @dev Count the number of set bits using Brian Kernighan's method.
    function _countBits(uint256 x) private pure returns (uint256 n) {
        while (x != 0) {
            x &= x - 1;

            unchecked {
                ++n;
            }
        }
    }
}
