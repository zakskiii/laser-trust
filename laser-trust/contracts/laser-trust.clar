;; LaserTrust - Zero-Knowledge Identity Verification Protocol
;; A decentralized identity system enabling selective disclosure of credentials

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-proof (err u104))
(define-constant err-expired (err u105))

;; Data Variables
(define-data-var oracle-threshold uint u3)
(define-data-var identity-atom-nonce uint u0)

;; Identity Atom NFT
(define-non-fungible-token identity-atom uint)

;; Data Maps
;; Identity Atoms store commitment hashes without revealing underlying data
(define-map identity-atoms
  uint
  {
    owner: principal,
    commitment-hash: (buff 32),
    credential-type: (string-ascii 64),
    issued-at: uint,
    expires-at: uint,
    verified: bool,
    oracle-confirmations: uint
  }
)

;; Credential Types define what can be proven
(define-map credential-types
  (string-ascii 64)
  {
    enabled: bool,
    min-oracle-confirmations: uint,
    description: (string-utf8 256)
  }
)

;; Oracle Registry for decentralized verification
(define-map oracle-registry
  principal
  {
    active: bool,
    reputation-score: uint,
    verifications-count: uint
  }
)

;; Oracle Verifications track which oracles verified each atom
(define-map oracle-verifications
  {atom-id: uint, oracle: principal}
  {verified: bool, timestamp: uint}
)

;; Trust Lasers - Cryptographic relationship pathways
(define-map trust-lasers
  {from: principal, to: principal}
  {
    strength: uint,
    created-at: uint,
    updated-at: uint,
    interaction-count: uint
  }
)

;; Reputation Scores derived from identity atoms and trust lasers
(define-map reputation-scores
  principal
  {
    total-score: uint,
    verified-atoms: uint,
    trust-connections: uint,
    last-updated: uint
  }
)

;; Read-only functions

(define-read-only (get-identity-atom (atom-id uint))
  (map-get? identity-atoms atom-id)
)

(define-read-only (get-atom-owner (atom-id uint))
  (ok (get owner (unwrap! (map-get? identity-atoms atom-id) err-not-found)))
)

(define-read-only (get-credential-type (cred-type (string-ascii 64)))
  (map-get? credential-types cred-type)
)

(define-read-only (get-oracle-info (oracle principal))
  (map-get? oracle-registry oracle)
)

(define-read-only (get-trust-laser (from principal) (to principal))
  (map-get? trust-lasers {from: from, to: to})
)

(define-read-only (get-reputation-score (user principal))
  (default-to 
    {total-score: u0, verified-atoms: u0, trust-connections: u0, last-updated: u0}
    (map-get? reputation-scores user)
  )
)

(define-read-only (is-atom-verified (atom-id uint))
  (match (map-get? identity-atoms atom-id)
    atom (ok (get verified atom))
    err-not-found
  )
)

;; Oracle Management

(define-public (register-oracle (oracle principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (map-set oracle-registry oracle
      {
        active: true,
        reputation-score: u100,
        verifications-count: u0
      }
    ))
  )
)

(define-public (deactivate-oracle (oracle principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (map-set oracle-registry oracle
      (merge (unwrap! (map-get? oracle-registry oracle) err-not-found)
        {active: false}
      )
    ))
  )
)

;; Credential Type Management

(define-public (register-credential-type 
  (cred-type (string-ascii 64))
  (min-confirmations uint)
  (description (string-utf8 256)))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (map-set credential-types cred-type
      {
        enabled: true,
        min-oracle-confirmations: min-confirmations,
        description: description
      }
    ))
  )
)

;; Identity Atom Functions

(define-public (mint-identity-atom 
  (commitment-hash (buff 32))
  (credential-type (string-ascii 64))
  (validity-period uint))
  (let
    (
      (atom-id (+ (var-get identity-atom-nonce) u1))
      (current-block block-height)
    )
    ;; Verify credential type exists and is enabled
    (asserts! 
      (get enabled (unwrap! (map-get? credential-types credential-type) err-not-found))
      err-not-found
    )
    
    ;; Mint NFT
    (try! (nft-mint? identity-atom atom-id tx-sender))
    
    ;; Store atom data
    (map-set identity-atoms atom-id
      {
        owner: tx-sender,
        commitment-hash: commitment-hash,
        credential-type: credential-type,
        issued-at: current-block,
        expires-at: (+ current-block validity-period),
        verified: false,
        oracle-confirmations: u0
      }
    )
    
    ;; Increment nonce
    (var-set identity-atom-nonce atom-id)
    (ok atom-id)
  )
)

(define-public (verify-atom (atom-id uint) (proof-valid bool))
  (let
    (
      (atom (unwrap! (map-get? identity-atoms atom-id) err-not-found))
      (oracle-info (unwrap! (map-get? oracle-registry tx-sender) err-unauthorized))
      (cred-type-info (unwrap! (map-get? credential-types (get credential-type atom)) err-not-found))
      (current-confirmations (get oracle-confirmations atom))
    )
    ;; Verify oracle is active
    (asserts! (get active oracle-info) err-unauthorized)
    
    ;; Verify atom hasn't expired
    (asserts! (< block-height (get expires-at atom)) err-expired)
    
    ;; Verify proof is valid
    (asserts! proof-valid err-invalid-proof)
    
    ;; Record oracle verification
    (map-set oracle-verifications 
      {atom-id: atom-id, oracle: tx-sender}
      {verified: true, timestamp: block-height}
    )
    
    ;; Update oracle stats
    (map-set oracle-registry tx-sender
      (merge oracle-info {verifications-count: (+ (get verifications-count oracle-info) u1)})
    )
    
    ;; Update atom confirmations
    (let ((new-confirmations (+ current-confirmations u1)))
      (map-set identity-atoms atom-id
        (merge atom {
          oracle-confirmations: new-confirmations,
          verified: (>= new-confirmations (get min-oracle-confirmations cred-type-info))
        })
      )
    )
    
    (ok true)
  )
)

;; Trust Laser Functions - Build reputation graphs

(define-public (create-trust-laser (to principal) (strength uint))
  (let
    (
      (existing (map-get? trust-lasers {from: tx-sender, to: to}))
    )
    (match existing
      laser 
        ;; Update existing laser
        (ok (map-set trust-lasers {from: tx-sender, to: to}
          (merge laser {
            strength: strength,
            updated-at: block-height,
            interaction-count: (+ (get interaction-count laser) u1)
          })
        ))
      ;; Create new laser
      (ok (map-set trust-lasers {from: tx-sender, to: to}
        {
          strength: strength,
          created-at: block-height,
          updated-at: block-height,
          interaction-count: u1
        }
      ))
    )
  )
)

;; Reputation Algebra - Calculate composite scores

(define-public (update-reputation)
  (let
    (
      (current-rep (get-reputation-score tx-sender))
      (atom-count (get verified-atoms current-rep))
      (trust-count (get trust-connections current-rep))
      ;; Simple reputation formula: (verified-atoms * 10) + (trust-connections * 5)
      (new-score (+ (* atom-count u10) (* trust-count u5)))
    )
    (ok (map-set reputation-scores tx-sender
      {
        total-score: new-score,
        verified-atoms: atom-count,
        trust-connections: trust-count,
        last-updated: block-height
      }
    ))
  )
)

;; Transfer identity atom (NFT transfer)
(define-public (transfer-atom (atom-id uint) (sender principal) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender sender) err-unauthorized)
    (try! (nft-transfer? identity-atom atom-id sender recipient))
    (ok (map-set identity-atoms atom-id
      (merge (unwrap! (map-get? identity-atoms atom-id) err-not-found)
        {owner: recipient}
      )
    ))
  )
)

;; Initialize common credential types
(begin
  (map-set credential-types "age-range"
    {enabled: true, min-oracle-confirmations: u2, description: u"Proves age within range without revealing exact age"}
  )
  (map-set credential-types "geographic-region"
    {enabled: true, min-oracle-confirmations: u2, description: u"Proves location within region without revealing exact address"}
  )
  (map-set credential-types "professional-cert"
    {enabled: true, min-oracle-confirmations: u3, description: u"Proves professional certification without revealing identity"}
  )
  (map-set credential-types "kyc-verified"
    {enabled: true, min-oracle-confirmations: u3, description: u"Proves KYC compliance without exposing personal data"}
  )
)