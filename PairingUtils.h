/*!
	@header			Pairing API
	@brief		APIs for performing cryptographic pairing between entities.
*/

#ifndef	__PairingUtils_h__
#define	__PairingUtils_h__

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <optional>
#include <chrono>
#include "SRP.hpp"
#include "TLV8.hpp"
#include <nlohmann/json_fwd.hpp>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/srp.h>
#include <cstddef>
#include <cstdint>
#include <array>
#include <chrono>

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingShowSetupCode_f
	@abstract	Generate a NUL-terminated setup code and show it to the user.
	@discussion	
	
	The setup code must be in the format XXX-XX-XXX where X is a 0-9 digit in ASCII (e.g. "123-45-678").
	If the setup code is being generated on-the-fly (recommended), it must come from a cryptographic random number generator.
	If the setup code is fixed (e.g. printed on a label and burnt into an EEPROM) then it must have been generated using 
	cryptographic random number generator during manufacturing (i.e. don't use a simple counter, manufacture date, region
	of origin, etc. since that can significantly improve an attackers ability to guess it).
*/
typedef int32_t ( *PairingShowSetupCode_f )( char *inBuffer, size_t inMaxLen, void *inContext );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingHideSetupCode_f
	@abstract	Hide any setup code that may be visible for this session.
*/
typedef void ( *PairingHideSetupCode_f )( void *inContext );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingPromptForSetupCode_f
	@abstract	Prompt the user for a setup code.
	@discussion	
	
	The expectation is that this callback will display a dialog and immediately return. When the user enters the setup code, 
	it should be set with PairingSessionSetSetupCode and then PairingSessionExchange should be called to resume the exchange 
	process. If the user cancels the setup code entry dialog, the pairing session can just be released.
	
	@param		inFlags				Flags for setup code prompt.
	@param		inDelaySeconds		< 0 means no delay. >= 0 means the UI must wait N seconds before trying again.
	@param		inContext			Context pointer provided by the delegate.
*/
typedef int32_t ( *PairingPromptForSetupCode_f )( int32_t inDelaySeconds, void *inContext );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingCopyIdentity_f
	@abstract	Optionally copy the identifier, get the Ed25519 public key, and/or get the secret key of this device.
*/
typedef int32_t
	( *PairingCopyIdentity_f )( 
		bool		inAllowCreate, 
		char **		outIdentifier, 
		uint8_t		outPK[ 32 ], 
		uint8_t		outSK[ 32 ], 
		void *		inContext );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingFindPeer_f
	@abstract	Find a peer's Ed25519 public key by its identifier.
*/
typedef int32_t
	( *PairingFindPeer_f )( 
		const void *	inIdentifierPtr, 
		size_t			inIdentifierLen, 
		uint8_t			outPK[ 32 ], 
		void *			inContext );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	PairingSavePeer_f
	@abstract	Save a peer's Ed25519 public key.
*/
typedef int32_t
	( *PairingSavePeer_f )( 
		const void *	inIdentifierPtr, 
		size_t			inIdentifierLen, 
		const uint8_t	inPK[ 32 ], 
		void *			inContext );

// PairingDelegate

typedef struct PairingDelegate
{
	void *							context = nullptr;
	PairingShowSetupCode_f			showSetupCode_f = 0;
	PairingHideSetupCode_f			hideSetupCode_f = 0;
	PairingPromptForSetupCode_f		promptForSetupCode_f = 0;
	PairingCopyIdentity_f			copyIdentity_f = 0;
	PairingFindPeer_f				findPeer_f = 0;
	PairingSavePeer_f				savePeer_f = 0;
}	PairingDelegate;

class PairingSession {
public:
	// Session Types
	enum class SessionType {
		SetupServer,
		VerifyServer
	};

	// Peer Information
	struct PeerInfo {
		std::string identifier;
		std::vector<uint8_t> publicKey;
		std::vector<uint8_t> signature;
		bool isAdmin{false};
		std::chrono::system_clock::time_point lastSeen;
	};

	// Identity management
	struct IdentityInfo {
		std::string identifier;
		std::vector<uint8_t> publicKey;
		std::vector<uint8_t> privateKey;
		std::vector<uint8_t> signature;
		bool isPrimary{false};
		std::chrono::system_clock::time_point createdAt;
		std::chrono::system_clock::time_point lastUsed;
	};

	// Constructor/Destructor
	PairingSession(const PairingDelegate& inDelegate = {}, SessionType inType = SessionType::SetupServer, std::string storagePath = std::filesystem::current_path());
	~PairingSession();

	// Move operations
	PairingSession(PairingSession&& other) noexcept;
	PairingSession& operator=(PairingSession&& other) noexcept;

	// Delete copy operations
	PairingSession(const PairingSession&) = delete;
	PairingSession& operator=(const PairingSession&) = delete;

	// Core Session Management
	void setIdentifier(std::string_view identifier);
	void setMaxTries(int maxTries);
	void setMTU(size_t mtu);

	// Setup Code Management
	void setSetupCode(std::string_view setupCode);

	// Pairing Exchange Functions
	std::pair<std::vector<uint8_t>, bool> exchange(const std::vector<uint8_t>& input);
	int32_t deriveKey( std::string_view salt, std::string_view info, size_t keyLen, std::vector<uint8_t>& outKey, bool setup = false, std::vector<uint8_t> optionalSecret = {});

	// Peer Management Functions
	int32_t savePeer(std::string_view identifier, const uint8_t peerPK[32], void *inContext);
	std::optional<PeerInfo> findPeer(std::string_view identifier);
	int32_t updatePeer(const PeerInfo& peer);
	int32_t deletePeer(std::string_view identifier);
	std::vector<PeerInfo> listPeers();

	// Identity management
	int32_t createIdentity();
	std::optional<IdentityInfo> loadIdentity();
	int32_t deleteIdentity();
	std::vector<IdentityInfo> listIdentities();

private:
	// Implementation details
	class Impl {
	public:
		Impl() = default;
		~Impl() = default;

		std::string identifier;
		std::string activeIdentifier;
		std::string setupCode;
		std::vector<uint8_t> inputBuf;
		std::vector<uint8_t> outputBuf;
		size_t outputFragmentOffset{0};
		bool outputDone{false};
		bool setupCodeFailed{false};
		bool showingSetupCode{false};
		uint8_t state{0};
		uint8_t requestMethod{0};
		PairingDelegate delegate;
	};
	std::unique_ptr<Impl> pImpl;

	// Core members
	PairingDelegate delegate;
	SessionType type;
	size_t mtuPayload{SIZE_MAX - 2};
	size_t mtuTotal{SIZE_MAX};
	std::string storagePath;

	// Crypto arrays
	std::array<uint8_t, 32> key;
	std::array<uint8_t, 32> ourCurvePK;
	std::array<uint8_t, 32> ourCurveSK;
	std::array<uint8_t, 32> ourEdPK;
	std::array<uint8_t, 32> ourEdSK;
	std::array<uint8_t, 32> peerCurvePK;
	std::array<uint8_t, 32> peerEdPK;
	std::array<uint8_t, 32> sharedSecret;

	// SRP data
	std::unique_ptr<SRPServer> srpContext;
	std::vector<uint8_t> srpPK;
	std::vector<uint8_t> srpSalt;
	std::vector<uint8_t> srpSharedSecret;

	// Handle setup server states
	int32_t handleSetupServerExchange(TLV8& responseBuf);
	int32_t handleVerifyServerExchange(TLV8& responseBuf);

	// Private helper functions
	int32_t progressInput();
	int32_t handleVerifyServerStart(TLV8& responseBuf);
	int32_t handleVerifyServerFinish(TLV8& responseBuf);
};

#endif // __PairingUtils_h__
