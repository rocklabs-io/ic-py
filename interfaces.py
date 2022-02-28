from ic.canister import Canister

candid_list = {
    'registry':"""type AddNodeOperatorPayload = record {
  node_operator_principal_id : opt principal;
  node_allowance : nat64;
  rewardable_nodes : vec record { text; nat32 };
  node_provider_principal_id : opt principal;
  dc_id : text;
};
type AddNodePayload = record {
  prometheus_metrics_endpoint : text;
  http_endpoint : text;
  xnet_endpoint : text;
  committee_signing_pk : vec nat8;
  node_signing_pk : vec nat8;
  transport_tls_cert : vec nat8;
  ni_dkg_dealing_encryption_pk : vec nat8;
  p2p_flow_endpoints : vec text;
};
type AddNodesToSubnetPayload = record {
  subnet_id : principal;
  node_ids : vec principal;
};
type AddOrRemoveDataCentersProposalPayload = record {
  data_centers_to_add : vec DataCenterRecord;
  data_centers_to_remove : vec text;
};
type BlessReplicaVersionPayload = record {
  node_manager_sha256_hex : text;
  release_package_url : text;
  sha256_hex : text;
  replica_version_id : text;
  release_package_sha256_hex : text;
  node_manager_binary_url : text;
  binary_url : text;
};
type CreateSubnetPayload = record {
  unit_delay_millis : nat64;
  max_instructions_per_round : nat64;
  features : SubnetFeatures;
  max_instructions_per_message : nat64;
  gossip_registry_poll_period_ms : nat32;
  max_ingress_bytes_per_message : nat64;
  dkg_dealings_per_block : nat64;
  max_block_payload_size : nat64;
  max_instructions_per_install_code : nat64;
  start_as_nns : bool;
  is_halted : bool;
  gossip_pfn_evaluation_period_ms : nat32;
  max_ingress_messages_per_block : nat64;
  max_number_of_canisters : nat64;
  gossip_max_artifact_streams_per_peer : nat32;
  advert_best_effort_percentage : opt nat32;
  replica_version_id : text;
  gossip_max_duplicity : nat32;
  gossip_max_chunk_wait_ms : nat32;
  dkg_interval_length : nat64;
  subnet_id_override : opt principal;
  ssh_backup_access : vec text;
  ingress_bytes_per_block_soft_cap : nat64;
  initial_notary_delay_millis : nat64;
  gossip_max_chunk_size : nat32;
  subnet_type : SubnetType;
  ssh_readonly_access : vec text;
  gossip_retransmission_request_ms : nat32;
  gossip_receive_check_cache_size : nat32;
  node_ids : vec principal;
};
type DataCenterRecord = record {
  id : text;
  gps : opt Gps;
  region : text;
  owner : text;
};
type DeleteSubnetPayload = record { subnet_id : opt principal };
type EcdsaConfig = record { quadruples_to_create_in_advance : nat32 };
type Gps = record { latitude : float32; longitude : float32 };
type NodeProvidersMonthlyXdrRewards = record {
  rewards : vec record { text; nat64 };
};
type NodeRewardRate = record { xdr_permyriad_per_node_per_month : nat64 };
type NodeRewardRates = record { rates : vec record { text; NodeRewardRate } };
type RecoverSubnetPayload = record {
  height : nat64;
  replacement_nodes : opt vec principal;
  subnet_id : principal;
  registry_store_uri : opt record { text; text; nat64 };
  state_hash : vec nat8;
  time_ns : nat64;
};
type RemoveNodeDirectlyPayload = record { node_id : principal };
type RemoveNodeOperatorsPayload = record {
  node_operators_to_remove : vec vec nat8;
};
type RemoveNodesPayload = record { node_ids : vec principal };
type RerouteCanisterRangePayload = record {
  range_end_inclusive : principal;
  range_start_inclusive : principal;
  destination_subnet : principal;
};
type Result = variant { Ok : principal; Err : text };
type Result_1 = variant { Ok : NodeProvidersMonthlyXdrRewards; Err : text };
type Result_2 = variant { Ok; Err : text };
type SetFirewallConfigPayload = record {
  ipv4_prefixes : vec text;
  firewall_config : text;
  ipv6_prefixes : vec text;
};
type SubnetFeatures = record {
  canister_sandboxing : bool;
  http_requests : bool;
  ecdsa_signatures : bool;
};
type SubnetType = variant { application; verified_application; system };
type UpdateNodeOperatorConfigPayload = record {
  node_operator_id : opt principal;
  node_allowance : opt nat64;
  rewardable_nodes : vec record { text; nat32 };
  dc_id : opt text;
};
type UpdateNodeRewardsTableProposalPayload = record {
  new_entries : vec record { text; NodeRewardRates };
};
type UpdateSubnetPayload = record {
  unit_delay_millis : opt nat64;
  max_duplicity : opt nat32;
  max_instructions_per_round : opt nat64;
  features : opt SubnetFeatures;
  set_gossip_config_to_default : bool;
  max_instructions_per_message : opt nat64;
  pfn_evaluation_period_ms : opt nat32;
  subnet_id : principal;
  max_ingress_bytes_per_message : opt nat64;
  dkg_dealings_per_block : opt nat64;
  max_block_payload_size : opt nat64;
  max_instructions_per_install_code : opt nat64;
  start_as_nns : opt bool;
  is_halted : opt bool;
  max_ingress_messages_per_block : opt nat64;
  max_number_of_canisters : opt nat64;
  ecdsa_config : opt EcdsaConfig;
  advert_best_effort_percentage : opt nat32;
  retransmission_request_ms : opt nat32;
  dkg_interval_length : opt nat64;
  registry_poll_period_ms : opt nat32;
  max_chunk_wait_ms : opt nat32;
  receive_check_cache_size : opt nat32;
  ssh_backup_access : opt vec text;
  max_chunk_size : opt nat32;
  initial_notary_delay_millis : opt nat64;
  max_artifact_streams_per_peer : opt nat32;
  subnet_type : opt SubnetType;
  ssh_readonly_access : opt vec text;
};
type UpdateSubnetReplicaVersionPayload = record {
  subnet_id : principal;
  replica_version_id : text;
};
type UpdateUnassignedNodesConfigPayload = record {
  replica_version : opt text;
  ssh_readonly_access : opt vec text;
};
service : {
  add_node : (AddNodePayload) -> (Result);
  add_node_operator : (AddNodeOperatorPayload) -> ();
  add_nodes_to_subnet : (AddNodesToSubnetPayload) -> ();
  add_or_remove_data_centers : (AddOrRemoveDataCentersProposalPayload) -> ();
  bless_replica_version : (BlessReplicaVersionPayload) -> ();
  clear_provisional_whitelist : () -> ();
  create_subnet : (CreateSubnetPayload) -> ();
  delete_subnet : (DeleteSubnetPayload) -> ();
  get_node_providers_monthly_xdr_rewards : () -> (Result_1) query;
  recover_subnet : (RecoverSubnetPayload) -> ();
  remove_node_directly : (RemoveNodeDirectlyPayload) -> ();
  remove_node_operators : (RemoveNodeOperatorsPayload) -> ();
  remove_nodes : (RemoveNodesPayload) -> ();
  remove_nodes_from_subnet : (RemoveNodesPayload) -> ();
  reroute_canister_range : (RerouteCanisterRangePayload) -> (Result_2);
  set_firewall_config : (SetFirewallConfigPayload) -> ();
  update_node_operator_config : (UpdateNodeOperatorConfigPayload) -> ();
  update_node_rewards_table : (UpdateNodeRewardsTableProposalPayload) -> ();
  update_subnet : (UpdateSubnetPayload) -> ();
  update_subnet_replica_version : (UpdateSubnetReplicaVersionPayload) -> ();
  update_unassigned_nodes_config : (UpdateUnassignedNodesConfigPayload) -> ();
}""",
    'governance':"""type AccountIdentifier = record { hash : vec nat8 };
type Action = variant {
  ManageNeuron : ManageNeuron;
  ExecuteNnsFunction : ExecuteNnsFunction;
  RewardNodeProvider : RewardNodeProvider;
  SetDefaultFollowees : SetDefaultFollowees;
  RewardNodeProviders : RewardNodeProviders;
  ManageNetworkEconomics : NetworkEconomics;
  ApproveGenesisKyc : ApproveGenesisKyc;
  AddOrRemoveNodeProvider : AddOrRemoveNodeProvider;
  Motion : Motion;
};
type AddHotKey = record { new_hot_key : opt principal };
type AddOrRemoveNodeProvider = record { change : opt Change };
type Amount = record { e8s : nat64 };
type ApproveGenesisKyc = record { principals : vec principal };
type Ballot = record { vote : int32; voting_power : nat64 };
type BallotInfo = record { vote : int32; proposal_id : opt NeuronId };
type By = variant { Memo : nat64 };
type Change = variant { ToRemove : NodeProvider; ToAdd : NodeProvider };
type ClaimOrRefresh = record { by : opt By };
type ClaimOrRefreshNeuronFromAccount = record {
  controller : opt principal;
  memo : nat64;
};
type ClaimOrRefreshNeuronFromAccountResponse = record { result : opt Result_1 };
type ClaimOrRefreshResponse = record { refreshed_neuron_id : opt NeuronId };
type Command = variant {
  Spawn : Spawn;
  Split : Split;
  Follow : Follow;
  ClaimOrRefresh : ClaimOrRefresh;
  Configure : Configure;
  RegisterVote : RegisterVote;
  DisburseToNeuron : DisburseToNeuron;
  MakeProposal : Proposal;
  MergeMaturity : MergeMaturity;
  Disburse : Disburse;
};
type Command_1 = variant {
  Error : GovernanceError;
  Spawn : SpawnResponse;
  Split : SpawnResponse;
  Follow : record {};
  ClaimOrRefresh : ClaimOrRefreshResponse;
  Configure : record {};
  RegisterVote : record {};
  DisburseToNeuron : SpawnResponse;
  MakeProposal : MakeProposalResponse;
  MergeMaturity : MergeMaturityResponse;
  Disburse : DisburseResponse;
};
type Command_2 = variant {
  Spawn : Spawn;
  Split : Split;
  ClaimOrRefresh : ClaimOrRefreshNeuronFromAccount;
  DisburseToNeuron : DisburseToNeuron;
  MergeMaturity : MergeMaturity;
  Disburse : Disburse;
};
type Configure = record { operation : opt Operation };
type Disburse = record {
  to_account : opt AccountIdentifier;
  amount : opt Amount;
};
type DisburseResponse = record { transfer_block_height : nat64 };
type DisburseToNeuron = record {
  dissolve_delay_seconds : nat64;
  kyc_verified : bool;
  amount_e8s : nat64;
  new_controller : opt principal;
  nonce : nat64;
};
type DissolveState = variant {
  DissolveDelaySeconds : nat64;
  WhenDissolvedTimestampSeconds : nat64;
};
type ExecuteNnsFunction = record { nns_function : int32; payload : vec nat8 };
type Follow = record { topic : int32; followees : vec NeuronId };
type Followees = record { followees : vec NeuronId };
type Governance = record {
  default_followees : vec record { int32; Followees };
  wait_for_quiet_threshold_seconds : nat64;
  node_providers : vec NodeProvider;
  economics : opt NetworkEconomics;
  latest_reward_event : opt RewardEvent;
  to_claim_transfers : vec NeuronStakeTransfer;
  short_voting_period_seconds : nat64;
  proposals : vec record { nat64; ProposalData };
  in_flight_commands : vec record { nat64; NeuronInFlightCommand };
  neurons : vec record { nat64; Neuron };
  genesis_timestamp_seconds : nat64;
};
type GovernanceError = record { error_message : text; error_type : int32 };
type IncreaseDissolveDelay = record {
  additional_dissolve_delay_seconds : nat32;
};
type ListNeurons = record {
  neuron_ids : vec nat64;
  include_neurons_readable_by_caller : bool;
};
type ListNeuronsResponse = record {
  neuron_infos : vec record { nat64; NeuronInfo };
  full_neurons : vec Neuron;
};
type ListProposalInfo = record {
  include_reward_status : vec int32;
  before_proposal : opt NeuronId;
  limit : nat32;
  exclude_topic : vec int32;
  include_status : vec int32;
};
type ListProposalInfoResponse = record { proposal_info : vec ProposalInfo };
type MakeProposalResponse = record { proposal_id : opt NeuronId };
type ManageNeuron = record {
  id : opt NeuronId;
  command : opt Command;
  neuron_id_or_subaccount : opt NeuronIdOrSubaccount;
};
type ManageNeuronResponse = record { command : opt Command_1 };
type MergeMaturity = record { percentage_to_merge : nat32 };
type MergeMaturityResponse = record {
  merged_maturity_e8s : nat64;
  new_stake_e8s : nat64;
};
type Motion = record { motion_text : text };
type NetworkEconomics = record {
  neuron_minimum_stake_e8s : nat64;
  max_proposals_to_keep_per_topic : nat32;
  neuron_management_fee_per_proposal_e8s : nat64;
  reject_cost_e8s : nat64;
  transaction_fee_e8s : nat64;
  neuron_spawn_dissolve_delay_seconds : nat64;
  minimum_icp_xdr_rate : nat64;
  maximum_node_provider_rewards_e8s : nat64;
};
type Neuron = record {
  id : opt NeuronId;
  controller : opt principal;
  recent_ballots : vec BallotInfo;
  kyc_verified : bool;
  not_for_profit : bool;
  maturity_e8s_equivalent : nat64;
  cached_neuron_stake_e8s : nat64;
  created_timestamp_seconds : nat64;
  aging_since_timestamp_seconds : nat64;
  hot_keys : vec principal;
  account : vec nat8;
  dissolve_state : opt DissolveState;
  followees : vec record { int32; Followees };
  neuron_fees_e8s : nat64;
  transfer : opt NeuronStakeTransfer;
};
type NeuronId = record { id : nat64 };
type NeuronIdOrSubaccount = variant {
  Subaccount : vec nat8;
  NeuronId : NeuronId;
};
type NeuronInFlightCommand = record {
  command : opt Command_2;
  timestamp : nat64;
};
type NeuronInfo = record {
  dissolve_delay_seconds : nat64;
  recent_ballots : vec BallotInfo;
  created_timestamp_seconds : nat64;
  state : int32;
  retrieved_at_timestamp_seconds : nat64;
  voting_power : nat64;
  age_seconds : nat64;
};
type NeuronStakeTransfer = record {
  to_subaccount : vec nat8;
  neuron_stake_e8s : nat64;
  from : opt principal;
  memo : nat64;
  from_subaccount : vec nat8;
  transfer_timestamp : nat64;
  block_height : nat64;
};
type NodeProvider = record { id : opt principal };
type Operation = variant {
  RemoveHotKey : RemoveHotKey;
  AddHotKey : AddHotKey;
  StopDissolving : record {};
  StartDissolving : record {};
  IncreaseDissolveDelay : IncreaseDissolveDelay;
  SetDissolveTimestamp : SetDissolveTimestamp;
};
type Proposal = record { url : text; action : opt Action; summary : text };
type ProposalData = record {
  id : opt NeuronId;
  failure_reason : opt GovernanceError;
  ballots : vec record { nat64; Ballot };
  proposal_timestamp_seconds : nat64;
  reward_event_round : nat64;
  failed_timestamp_seconds : nat64;
  reject_cost_e8s : nat64;
  latest_tally : opt Tally;
  decided_timestamp_seconds : nat64;
  proposal : opt Proposal;
  proposer : opt NeuronId;
  executed_timestamp_seconds : nat64;
};
type ProposalInfo = record {
  id : opt NeuronId;
  status : int32;
  topic : int32;
  failure_reason : opt GovernanceError;
  ballots : vec record { nat64; Ballot };
  proposal_timestamp_seconds : nat64;
  reward_event_round : nat64;
  failed_timestamp_seconds : nat64;
  reject_cost_e8s : nat64;
  latest_tally : opt Tally;
  reward_status : int32;
  decided_timestamp_seconds : nat64;
  proposal : opt Proposal;
  proposer : opt NeuronId;
  executed_timestamp_seconds : nat64;
};
type RegisterVote = record { vote : int32; proposal : opt NeuronId };
type RemoveHotKey = record { hot_key_to_remove : opt principal };
type Result = variant { Ok; Err : GovernanceError };
type Result_1 = variant { Error : GovernanceError; NeuronId : NeuronId };
type Result_2 = variant { Ok : Neuron; Err : GovernanceError };
type Result_3 = variant { Ok : NeuronInfo; Err : GovernanceError };
type RewardEvent = record {
  day_after_genesis : nat64;
  actual_timestamp_seconds : nat64;
  distributed_e8s_equivalent : nat64;
  settled_proposals : vec NeuronId;
};
type RewardMode = variant {
  RewardToNeuron : RewardToNeuron;
  RewardToAccount : RewardToAccount;
};
type RewardNodeProvider = record {
  node_provider : opt NodeProvider;
  reward_mode : opt RewardMode;
  amount_e8s : nat64;
};
type RewardNodeProviders = record { rewards : vec RewardNodeProvider };
type RewardToAccount = record { to_account : opt AccountIdentifier };
type RewardToNeuron = record { dissolve_delay_seconds : nat64 };
type SetDefaultFollowees = record {
  default_followees : vec record { int32; Followees };
};
type SetDissolveTimestamp = record { dissolve_timestamp_seconds : nat64 };
type Spawn = record { new_controller : opt principal };
type SpawnResponse = record { created_neuron_id : opt NeuronId };
type Split = record { amount_e8s : nat64 };
type Tally = record {
  no : nat64;
  yes : nat64;
  total : nat64;
  timestamp_seconds : nat64;
};
service : (Governance) -> {
  claim_gtc_neurons : (principal, vec NeuronId) -> (Result);
  claim_or_refresh_neuron_from_account : (ClaimOrRefreshNeuronFromAccount) -> (
      ClaimOrRefreshNeuronFromAccountResponse,
    );
  get_full_neuron : (nat64) -> (Result_2) query;
  get_neuron_ids : () -> (vec nat64) query;
  get_neuron_info : (nat64) -> (Result_3) query;
  get_pending_proposals : () -> (vec ProposalInfo) query;
  get_proposal_info : (nat64) -> (opt ProposalInfo) query;
  list_neurons : (ListNeurons) -> (ListNeuronsResponse) query;
  list_proposals : (ListProposalInfo) -> (ListProposalInfoResponse) query;
  manage_neuron : (ManageNeuron) -> (ManageNeuronResponse);
  transfer_gtc_neuron : (NeuronId, NeuronId) -> (Result);
}
""",
    'ledger':"""type ICPTs = record {
     e8s : nat64;
};

type Duration = record {
    secs: nat64;
    nanos: nat32;
};

type TimeStamp = record {
    timestamp_nanos: nat64;
};

type ArchiveOptions = record {
    node_max_memory_size_bytes: opt nat32;
    max_message_size_bytes: opt nat32;
    controller_id: principal;
};

type BlockHeight = nat64;
type Memo = nat64;
type AccountIdentifier = text;
type SubAccount = vec nat8;

type Transfer = variant {
    Burn: record {
        from: AccountIdentifier;
        amount: ICPTs;
    };
    Mint: record {
        to: AccountIdentifier;
        amount: ICPTs;
    };
    Send: record {
        from: AccountIdentifier;
        to: AccountIdentifier;
        amount: ICPTs;
    };
};

type Transaction = record {
    transfer: Transfer;
    memo: Memo;
    created_at: BlockHeight;
};

type SendArgs = record {
    memo: Memo;
    amount: ICPTs;
    fee: ICPTs;
    from_subaccount: opt SubAccount;
    to: AccountIdentifier;
    created_at_time: opt TimeStamp;
};

type NotifyCanisterArgs = record {
    block_height: BlockHeight;
    max_fee: ICPTs;
    from_subaccount: opt SubAccount;
    to_canister: principal;
    to_subaccount: opt SubAccount;
};

type AccountBalanceArgs = record {
    account: AccountIdentifier;
};

type LedgerCanisterInitPayload = record {
    minting_account: AccountIdentifier;
    initial_values: vec record {AccountIdentifier; ICPTs};
    max_message_size_bytes: opt nat32;
    transaction_window: opt Duration;
    archive_options: opt ArchiveOptions;
    send_whitelist: vec record {principal};
};

service: (LedgerCanisterInitPayload) -> {
  send_dfx : (SendArgs) -> (BlockHeight);
  notify_dfx: (NotifyCanisterArgs) -> ();
  account_balance_dfx : (AccountBalanceArgs) -> (ICPTs) query;
}""",
    'cycles_minting': """type CyclesResponse = variant {
    Refunded : record { text; opt nat64 };
    CanisterCreated : principal;
    ToppedUp;
};
type ICPTs = record { e8s : nat64 };
type Result = variant { Ok : CyclesResponse; Err : text };
type TransactionNotification = record {
    to : principal;
    to_subaccount : opt vec nat8;
    from : principal;
    memo : nat64;
    from_subaccount : opt vec nat8;
    amount : ICPTs;
    block_height : nat64;
};
type SetAuthorizedSubnetworkListArgs = record {
    who : opt principal;
    subnets : vec principal;
};
type IcpXdrConversionRate = record {
    timestamp_seconds : nat64;
    xdr_permyriad_per_icp : nat64;
};
type IcpXdrConversionRateCertifiedResponse = record {
    data: IcpXdrConversionRate;
    hash_tree: vec nat8;
    certificate: vec nat8;
};
service : {
    set_authorized_subnetwork_list : (SetAuthorizedSubnetworkListArgs) -> ();
    transaction_notification : (TransactionNotification) -> (Result);
    get_icp_xdr_conversion_rate : () -> (IcpXdrConversionRateCertifiedResponse) query;
    get_average_icp_xdr_conversion_rate : () -> (IcpXdrConversionRateCertifiedResponse) query;
}""",
    'genesis_token':"""type AccountState = record {
  authenticated_principal_id : opt principal;
  successfully_transferred_neurons : vec TransferredNeuron;
  has_donated : bool;
  failed_transferred_neurons : vec TransferredNeuron;
  neuron_ids : vec NeuronId;
  has_claimed : bool;
  has_forwarded : bool;
  icpts : nat32;
};
type NeuronId = record { id : nat64 };
type Result = variant { Ok : vec NeuronId; Err : text };
type Result_1 = variant { Ok; Err : text };
type Result_2 = variant { Ok : AccountState; Err : text };
type TransferredNeuron = record {
  error : opt text;
  timestamp_seconds : nat64;
  neuron_id : opt NeuronId;
};
service : {
  balance : (text) -> (nat32) query;
  claim_neurons : (text) -> (Result);
  donate_account : (text) -> (Result_1);
  forward_all_unclaimed_accounts : (null) -> (Result_1);
  get_account : (text) -> (Result_2) query;
  len : () -> (nat16) query;
  total : () -> (nat32) query;
}""",
    'nns':"""type AccountIdentifier = text;
type AttachCanisterRequest = record {
  name: text;
  canister_id: principal;
};
type AttachCanisterResponse = variant {
  Ok: null;
  CanisterAlreadyAttached: null;
  NameAlreadyTaken: null;
  NameTooLong: null;
  CanisterLimitExceeded: null;
};
type SubAccount = vec nat8;
type SubAccountDetails = record {
  name: text;
  sub_account: SubAccount;
  account_identifier: AccountIdentifier;
};
type CreateSubAccountResponse = variant {
  Ok: SubAccountDetails;
  AccountNotFound: null;
  NameTooLong: null;
  SubAccountLimitExceeded: null;
};
type DetachCanisterRequest = record {
  canister_id: principal;
};
type DetachCanisterResponse = variant {
  Ok: null;
  CanisterNotFound: null;
};
type HardwareWalletAccountDetails = record {
  name: text;
  account_identifier: AccountIdentifier;
};
type AccountDetails = record {
  account_identifier: AccountIdentifier;
  hardware_wallet_accounts: vec HardwareWalletAccountDetails;
  sub_accounts: vec SubAccountDetails;
};
type GetAccountResponse = variant {
  Ok: AccountDetails;
  AccountNotFound: null;
};
type CanisterDetails = record {
  name: text;
  canister_id: principal;
};
type BlockHeight = nat64;
type Stats = record {
  latest_transaction_block_height: BlockHeight;
  seconds_since_last_ledger_sync: nat64;
  sub_accounts_count: nat64;
  hardware_wallet_accounts_count: nat64;
  accounts_count: nat64;
  earliest_transaction_block_height: BlockHeight;
  transactions_count: nat64;
  block_height_synced_up_to: opt nat64;
  latest_transaction_timestamp_nanos: nat64;
  earliest_transaction_timestamp_nanos: nat64;
};
type GetTransactionsRequest = record {
  page_size: nat8;
  offset: nat32;
  account_identifier: AccountIdentifier;
};
type Timestamp = record {
  timestamp_nanos: nat64;
};
type ICPTs = record {
  e8s: nat64;
};
type Send = record {
  to: AccountIdentifier;
  fee: ICPTs;
  amount: ICPTs;
};
type Receive = record {
  fee: ICPTs;
  from: AccountIdentifier;
  amount: ICPTs;
};
type Transfer = variant {
  Burn: record {
    amount: ICPTs;
  };
  Mint: record {
    amount: ICPTs;
  };
  Send: Send;
  Receive: Receive;
};
type Transaction = record {
  memo: nat64;
  timestamp: Timestamp;
  block_height: BlockHeight;
  transfer: Transfer;
};
type GetTransactionsResponse = record {
  total: nat32;
  transactions: vec Transaction;
};
type HeaderField = record {text; text};
type HttpRequest = record {
  url: text;
  method: text;
  body: vec nat8;
  headers: vec HeaderField;
};
type HttpResponse = record {
  body: vec nat8;
  headers: vec HeaderField;
  status_code: nat16;
};
type RegisterHardwareWalletRequest = record {
  name: text;
  account_identifier: AccountIdentifier;
};
type RegisterHardwareWalletResponse = variant {
  Ok: null;
  AccountNotFound: null;
  HardwareWalletAlreadyRegistered: null;
  HardwareWalletLimitExceeded: null;
  NameTooLong: null;
};
type RemoveHardwareWalletRequest = record {
  account_identifier: AccountIdentifier;
};
type RemoveHardwareWalletResponse = variant {
  Ok: null;
  HardwareWalletNotFound: null;
};
type RenameSubAccountRequest = record {
  new_name: text;
  account_identifier: AccountIdentifier;
};
type RenameSubAccountResponse = variant {
  Ok: null;
  AccountNotFound: null;
  SubAccountNotFound: null;
  NameTooLong: null;
};
service : {
  add_account: () -> (AccountIdentifier);
  attach_canister: (AttachCanisterRequest) -> (AttachCanisterResponse);
  create_sub_account: (text) -> (CreateSubAccountResponse);
  detach_canister: (DetachCanisterRequest) -> (DetachCanisterResponse);
  get_account: () -> (GetAccountResponse) query;
  get_canisters: () -> (vec CanisterDetails) query;
  get_icp_to_cycles_conversion_rate: () -> (nat64) query;
  get_stats: () -> (Stats) query;
  get_transactions: (GetTransactionsRequest) -> (GetTransactionsResponse) query;
  http_request: (HttpRequest) -> (HttpResponse) query;
  register_hardware_wallet: (RegisterHardwareWalletRequest) -> (RegisterHardwareWalletResponse);
  remove_hardware_wallet: (RemoveHardwareWalletRequest) -> (RemoveHardwareWalletResponse);
  rename_sub_account: (RenameSubAccountRequest) -> (RenameSubAccountResponse);
}""",
    'candid': """type HttpRequest = record {
  url : text;
  method : text;
  body : vec nat8;
  headers : vec record { text; text };
};
type HttpResponse = record {
  body : vec nat8;
  headers : vec record { text; text };
  status_code : nat16;
};
type Result = variant { Ok; Err : text };
service : {
  binding : (text, text) -> (opt text) query;
  did_to_js : (text) -> (opt text) query;
  http_request : (HttpRequest) -> (HttpResponse) query;
  subtype : (text, text) -> (Result) query;
}"""
}

nnsConfig = {

     'registry': 'rwlgt-iiaaa-aaaaa-aaaaa-cai',
     'governance': 'rrkah-fqaaa-aaaaa-aaaaq-cai',
     'ledger': 'ryjl3-tyaaa-aaaaa-aaaba-cai',
     'cycles_minting': 'rkp4c-7iaaa-aaaaa-aaaca-cai',
     'genesis_token': 'renrk-eyaaa-aaaaa-aaada-cai',
     'nns': 'qoctq-giaaa-aaaaa-aaaea-cai',
     'candid': 'a4gq6-oaaaa-aaaab-qaa4q-cai',
     #      'identity': 'rdmx6-jaaaa-aaaaa-aaadq-cai',#x
     #      'lifeline': 'rno2w-sqaaa-aaaaa-aaacq-cai',#x
     #      'root': 'r7inp-6aaaa-aaaaa-aaabq-cai',#x
     #     'ic_management': 'aaaaa-aa',
}

class Interfaces:
    def __init__(self, agent):
        for canisterName, canisterId in nnsConfig.items():
            candid = candid_list[canisterName]
            print(canisterName, canisterId, candid[:100])
            setattr(self, canisterName, Canister(agent, canisterId, candid))
