"""
BCS Command-Line Interface (CLI)
================================
User-facing command-line client for BCS (Bidirectional Currency System).

Entry point::

    $ bcs --help
    $ bcs wallet create --label "personal"
    $ bcs tx transfer --from <addr> --to <addr> --amount 1000000000
    $ bcs offline enable

Dependencies:
    pip install click rich pyyaml

Architecture reference: architecture_design.md §2.7 (Wallet/Client)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import click

# --------------------------------------------------------------------------- #
# Rich/colored output helpers (graceful fallback)
# --------------------------------------------------------------------------- #
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    _console = Console()
    HAS_RICH = True
except ImportError:
    _console = None  # type: ignore
    HAS_RICH = False


def _print(text: str = "", style: str = "") -> None:
    """Print text, using rich if available."""
    if HAS_RICH and _console:
        _console.print(text, style=style)
    else:
        click.echo(text)


def _success(text: str) -> None:
    _print(text, style="bold green")


def _error(text: str) -> None:
    _print(text, style="bold red")


def _warning(text: str) -> None:
    _print(text, style="bold yellow")


def _info(text: str) -> None:
    _print(text, style="cyan")


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG: dict[str, Any] = {
    "wallet_db": "~/.bcs/wallet.db",
    "balance_cache": "~/.bcs/balance_cache.db",
    "offline_db": "~/.bcs/offline.db",
    "node_rpc": "http://localhost:8080",
    "node_grpc": "localhost:50051",
    "fee_rate": 1000,
    "default_confirmations": 1,
}


def _resolve_path(path_str: str) -> str:
    """Expand user home and make absolute."""
    return str(Path(path_str).expanduser().resolve())


def _load_config(config_path: Optional[str]) -> dict[str, Any]:
    """Load configuration from YAML or JSON, merge with defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if not config_path:
        # Try default config locations
        candidates = [
            Path.home() / ".bcs" / "config.yaml",
            Path.home() / ".bcs" / "config.yml",
            Path.home() / ".bcs" / "config.json",
        ]
        for cand in candidates:
            if cand.exists():
                config_path = str(cand)
                break

    if config_path and Path(config_path).exists():
        ext = Path(config_path).suffix.lower()
        with open(config_path, "r", encoding="utf-8") as f:
            if ext in (".yaml", ".yml"):
                try:
                    import yaml
                    user_cfg = yaml.safe_load(f) or {}
                except ImportError:
                    _warning("PyYAML not installed, skipping YAML config")
                    user_cfg = {}
            else:
                user_cfg = json.load(f)
        cfg.update(user_cfg)

    # Resolve paths
    for key in ("wallet_db", "balance_cache", "offline_db"):
        cfg[key] = _resolve_path(cfg[key])
    return cfg


# --------------------------------------------------------------------------- #
# Context object passed between click commands
# --------------------------------------------------------------------------- #

class BCSContext:
    """Shared context for all BCS CLI commands."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._wallet: Optional[Any] = None
        self._tracker: Optional[Any] = None
        self._offline_mgr: Optional[Any] = None
        self._node_client: Optional[Any] = None

    def wallet(self) -> Any:
        from wallet import Wallet
        if self._wallet is None:
            self._wallet = Wallet(self.config["wallet_db"])
            self._wallet.init_database()
        return self._wallet

    def tracker(self) -> Any:
        from balance import BalanceTracker
        if self._tracker is None:
            self._tracker = BalanceTracker(self.config["balance_cache"])
        return self._tracker

    def offline_mgr(self) -> Any:
        from offline_mode import OfflineModeManager
        if self._offline_mgr is None:
            self._offline_mgr = OfflineModeManager(self.config["offline_db"])
        return self._offline_mgr

    def node_client(self) -> Any:
        """Return a node client stub or real client."""
        if self._node_client is None:
            # In production this would instantiate bcs_sdk.client
            from balance import NodeClientStub
            self._node_client = NodeClientStub()
        return self._node_client


# --------------------------------------------------------------------------- #
# Password prompt helper
# --------------------------------------------------------------------------- #

def _get_password(ctx: click.Context, password: Optional[str]) -> str:
    """Return password from option or secure prompt."""
    if password:
        return password
    return click.prompt("Wallet password", hide_input=True, confirmation_prompt=False)


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    help="Path to YAML/JSON configuration file.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[str], verbose: bool) -> None:
    """
    BCS Command-Line Interface
    ==========================

    The BCS (Bidirectional Currency System) CLI provides wallet management,
    transaction creation, offline mode, identity operations, and node control.

    Examples::

        \b
        $ bcs wallet create --label "personal"
        $ bcs wallet list
        $ bcs tx transfer --from <addr> --to <addr> --amount 1000000000
        $ bcs offline enable
        $ bcs gov params

    Documentation: https://docs.bcs-chain.org
    """
    cfg = _load_config(config_path)
    ctx.obj = BCSContext(cfg)
    if verbose:
        _info(f"Config loaded: wallet_db={cfg['wallet_db']}")


# --------------------------------------------------------------------------- #
# wallet group
# --------------------------------------------------------------------------- #

@cli.group()
def wallet() -> None:
    """Wallet management: create, list, inspect keys and balances."""
    pass


@wallet.command(name="create")
@click.option("--label", default="", help="Human-readable label for the new address.")
@click.option("--password", default="", help="Wallet password (or will be prompted).")
@click.option("--mnemonic-out", type=click.Path(), help="Optional file to write mnemonic.")
@click.pass_context
def wallet_create(
    ctx: click.Context,
    label: str,
    password: str,
    mnemonic_out: Optional[str],
) -> None:
    """Create a new wallet address with a fresh secp256k1 keypair."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    address = w.create_new(label=label, password=pwd)
    _success(f"Created new wallet address: {address}")
    if label:
        _info(f"  Label: {label}")

    # Export mnemonic
    mnemonic = w.export_mnemonic(address, password=pwd)
    if mnemonic_out:
        with open(mnemonic_out, "w", encoding="utf-8") as f:
            f.write(mnemonic + "\n")
        _info(f"  Mnemonic written to: {mnemonic_out}")
    else:
        _warning("  IMPORTANT: Write down your mnemonic phrase to recover this wallet:")
        _print(f"  {mnemonic}")


@wallet.command(name="list")
@click.pass_context
def wallet_list(ctx: click.Context) -> None:
    """List all wallet addresses with labels."""
    bcs_ctx: BCSContext = ctx.obj
    w = bcs_ctx.wallet()
    addrs = w.list_addresses()
    if not addrs:
        _info("No addresses in wallet.")
        return

    if HAS_RICH:
        table = Table(title="BCS Wallet Addresses", box=box.ROUNDED)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Label", style="green")
        table.add_column("Created", style="dim")
        for addr in addrs:
            info = w.get_address_info(addr)
            created = info.get("created_at", 0)
            dt = __import__("datetime").datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M")
            table.add_row(addr, info.get("label", ""), dt)
        _console.print(table)
    else:
        click.echo("Address                              | Label")
        click.echo("-" * 50)
        for addr in addrs:
            info = w.get_address_info(addr)
            click.echo(f"{addr} | {info.get('label', '')}")


@wallet.command(name="balance")
@click.argument("address", required=False)
@click.pass_context
def wallet_balance(ctx: click.Context, address: Optional[str]) -> None:
    """Query N balance for an address (defaults to first wallet address)."""
    bcs_ctx: BCSContext = ctx.obj
    w = bcs_ctx.wallet()
    tracker = bcs_ctx.tracker()

    if not address:
        addrs = w.list_addresses()
        if not addrs:
            _error("No addresses in wallet. Provide an address or create a wallet first.")
            raise click.Abort()
        address = addrs[0]

    bal = tracker.get_balance(address)
    if HAS_RICH:
        table = Table(title=f"Balance for {address[:20]}...", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Amount (nanoN)", justify="right", style="green")
        table.add_row("Total Balance", f"{bal['n_balance']:,}")
        table.add_row("Available", f"{bal['n_available']:,}")
        table.add_row("Locked", f"{bal['n_locked']:,}")
        table.add_row("Pending", f"{bal['n_pending']:,}")
        _console.print(table)
    else:
        click.echo(f"Balance for {address}:")
        click.echo(f"  Total:     {bal['n_balance']:,} nanoN")
        click.echo(f"  Available: {bal['n_available']:,} nanoN")
        click.echo(f"  Locked:    {bal['n_locked']:,} nanoN")
        click.echo(f"  Pending:   {bal['n_pending']:,} nanoN")


@wallet.command(name="history")
@click.argument("address", required=False)
@click.option("--limit", default=20, help="Max number of transactions to show.")
@click.pass_context
def wallet_history(ctx: click.Context, address: Optional[str], limit: int) -> None:
    """Show transaction history for an address."""
    bcs_ctx: BCSContext = ctx.obj
    w = bcs_ctx.wallet()
    tracker = bcs_ctx.tracker()

    if not address:
        addrs = w.list_addresses()
        if not addrs:
            _error("No addresses in wallet.")
            raise click.Abort()
        address = addrs[0]

    hist = tracker.get_transaction_history(address, limit=limit)
    if not hist:
        _info(f"No transaction history for {address}.")
        return

    if HAS_RICH:
        table = Table(title=f"Transaction History ({address[:16]}...)", box=box.ROUNDED)
        table.add_column("Tx Hash", no_wrap=True, style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Direction", style="green")
        table.add_column("Amount", justify="right")
        table.add_column("Block", justify="right", style="dim")
        for entry in hist:
            table.add_row(
                entry["tx_hash"][:24] + "...",
                str(entry["tx_type"]),
                entry["direction"],
                f"{entry['amount']:,}",
                str(entry["block_height"]),
            )
        _console.print(table)
    else:
        click.echo(f"History for {address}:")
        for entry in hist:
            click.echo(
                f"  {entry['tx_hash'][:20]}... type={entry['tx_type']} "
                f"dir={entry['direction']} amount={entry['amount']:,} "
                f"block={entry['block_height']}"
            )


@wallet.command(name="import-private-key")
@click.argument("private_key_hex")
@click.option("--label", default="", help="Label for imported address.")
@click.option("--password", default="", help="Wallet password.")
@click.pass_context
def wallet_import_privkey(
    ctx: click.Context, private_key_hex: str, label: str, password: str
) -> None:
    """Import a wallet from a 32-byte private key (64 hex chars)."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    address = w.import_from_private_key(private_key_hex, label=label, password=pwd)
    _success(f"Imported address: {address}")


@wallet.command(name="import-mnemonic")
@click.argument("mnemonic")
@click.option("--label", default="", help="Label for recovered address.")
@click.option("--password", default="", help="Wallet password.")
@click.pass_context
def wallet_import_mnemonic(
    ctx: click.Context, mnemonic: str, label: str, password: str
) -> None:
    """Recover a wallet from a BIP39 mnemonic phrase."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    address = w.import_from_mnemonic(mnemonic, label=label, password=pwd)
    _success(f"Recovered address: {address}")


# --------------------------------------------------------------------------- #
# tx group
# --------------------------------------------------------------------------- #

@cli.group()
def tx() -> None:
    """Transaction operations: transfer, sale, wage, sign, broadcast."""
    pass


def _load_tx_file(tx_file: str) -> Any:
    """Load a Transaction from JSON file."""
    from exporter import TxExporter
    exporter = TxExporter()
    txs = exporter.import_from_file(tx_file)
    if not txs:
        raise ValueError("No transactions found in file")
    return txs[0]


def _save_tx_file(tx: Any, tx_file: str) -> None:
    """Save a Transaction to JSON file."""
    from exporter import TxExporter
    exporter = TxExporter()
    exporter.export_to_file([tx], tx_file)


@tx.command(name="transfer")
@click.option("--from", "from_addr", required=True, help="Sender address.")
@click.option("--to", "recipient", required=True, help="Recipient address.")
@click.option("--amount", required=True, type=int, help="Amount in nanoN.")
@click.option("--fee", default=0, type=int, help="Transaction fee in nanoN (0 = auto-estimate).")
@click.option("--password", default="", help="Wallet password.")
@click.option("--output", "-o", type=click.Path(), help="Save signed tx to file.")
@click.option("--broadcast", is_flag=True, help="Immediately broadcast to network (requires node).")
@click.pass_context
def tx_transfer(
    ctx: click.Context,
    from_addr: str,
    recipient: str,
    amount: int,
    fee: int,
    password: str,
    output: Optional[str],
    broadcast: bool,
) -> None:
    """Create and sign a standard N transfer transaction."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    tracker = bcs_ctx.tracker()

    # Get UTXOs
    utxos = tracker.get_utxos(from_addr)
    if not utxos:
        _error(f"No UTXOs available for {from_addr}")
        raise click.Abort()

    from tx_creator import TxCreator
    creator = TxCreator(fee_rate=bcs_ctx.config.get("fee_rate", 1000))
    if fee == 0:
        fee = creator.estimate_fee(num_inputs=max(1, len(utxos) // 2), num_outputs=2)
        _info(f"Auto-estimated fee: {fee} nanoN")

    tx = creator.create_transfer(
        wallet=w,
        from_addr=from_addr,
        recipient=recipient,
        amount=amount,
        fee=fee,
        password=pwd,
        available_utxos=utxos,
    )
    _success(f"Transfer tx created: {tx.hash()}")

    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")

    if broadcast:
        _warning("Broadcast not implemented in this stub — use export + node broadcast")


@tx.command(name="sale")
@click.option("--from", "from_addr", required=True, help="Seller address.")
@click.option("--buyer", required=True, help="Buyer address.")
@click.option(
    "--d-amount",
    "--external-amount",
    required=True,
    type=int,
    help="External payment amount used as the phi calculation base.",
)
@click.option("--n-amount", required=True, type=int, help="N amount to transfer to buyer.")
@click.option("--external-currency", default="", help="Optional external currency/unit label.")
@click.option("--external-payment-ref", default="", help="Optional bank/cash/gateway/invoice reference.")
@click.option("--fee", default=0, type=int, help="Transaction fee in nanoN.")
@click.option("--password", default="", help="Wallet password.")
@click.option("--output", "-o", type=click.Path(), help="Save signed tx to file.")
@click.pass_context
def tx_sale(
    ctx: click.Context,
    from_addr: str,
    buyer: str,
    d_amount: int,
    n_amount: int,
    external_currency: str,
    external_payment_ref: str,
    fee: int,
    password: str,
    output: Optional[str],
) -> None:
    """Create and sign a TRANSFER_SALE transaction (seller perspective)."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    tracker = bcs_ctx.tracker()
    utxos = tracker.get_utxos(from_addr)
    if not utxos:
        _error(f"No UTXOs available for {from_addr}")
        raise click.Abort()

    from tx_creator import TxCreator
    creator = TxCreator(fee_rate=bcs_ctx.config.get("fee_rate", 1000))
    if fee == 0:
        fee = creator.estimate_fee(num_inputs=max(1, len(utxos) // 2), num_outputs=2, extra_size=128)
        _info(f"Auto-estimated fee: {fee} nanoN")

    tx = creator.create_sale(
        wallet=w,
        from_addr=from_addr,
        buyer=buyer,
        d_amount=d_amount,
        n_amount=n_amount,
        external_currency=external_currency,
        external_payment_ref=external_payment_ref,
        fee=fee,
        password=pwd,
        available_utxos=utxos,
    )
    _success(f"Sale tx created: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")


@tx.command(name="wage")
@click.option("--from", "from_addr", required=True, help="Worker address.")
@click.option("--employer", required=True, help="Employer address.")
@click.option(
    "--d-amount",
    "--external-amount",
    required=True,
    type=int,
    help="External wage amount used as the psi calculation base.",
)
@click.option("--n-amount", required=True, type=int, help="N amount to transfer to employer.")
@click.option("--external-currency", default="", help="Optional external currency/unit label.")
@click.option("--external-payment-ref", default="", help="Optional payroll/bank/cash/gateway reference.")
@click.option("--fee", default=0, type=int, help="Transaction fee in nanoN.")
@click.option("--password", default="", help="Wallet password.")
@click.option("--output", "-o", type=click.Path(), help="Save signed tx to file.")
@click.pass_context
def tx_wage(
    ctx: click.Context,
    from_addr: str,
    employer: str,
    d_amount: int,
    n_amount: int,
    external_currency: str,
    external_payment_ref: str,
    fee: int,
    password: str,
    output: Optional[str],
) -> None:
    """Create and sign a TRANSFER_WAGE transaction (worker perspective)."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    tracker = bcs_ctx.tracker()
    utxos = tracker.get_utxos(from_addr)
    if not utxos:
        _error(f"No UTXOs available for {from_addr}")
        raise click.Abort()

    from tx_creator import TxCreator
    creator = TxCreator(fee_rate=bcs_ctx.config.get("fee_rate", 1000))
    if fee == 0:
        fee = creator.estimate_fee(num_inputs=max(1, len(utxos) // 2), num_outputs=2, extra_size=128)
        _info(f"Auto-estimated fee: {fee} nanoN")

    tx = creator.create_wage(
        wallet=w,
        from_addr=from_addr,
        employer=employer,
        d_amount=d_amount,
        n_amount=n_amount,
        external_currency=external_currency,
        external_payment_ref=external_payment_ref,
        fee=fee,
        password=pwd,
        available_utxos=utxos,
    )
    _success(f"Wage tx created: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")


@tx.command(name="sign")
@click.argument("tx_file", type=click.Path(exists=True))
@click.option("--address", required=True, help="Address to sign with.")
@click.option("--password", default="", help="Wallet password.")
@click.option("--output", "-o", type=click.Path(), help="Output file for signed tx.")
@click.pass_context
def tx_sign(
    ctx: click.Context,
    tx_file: str,
    address: str,
    password: str,
    output: Optional[str],
) -> None:
    """Sign an existing unsigned transaction file."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()

    tx = _load_tx_file(tx_file)
    sighash = tx.signing_hash()
    unlock = w.build_unlock_script(address, sighash, password=pwd)

    for i in range(len(tx.inputs)):
        tx.inputs[i].unlock_script = unlock
    tx.witnesses = [unlock]

    _success(f"Transaction signed: {tx.hash()}")
    out_path = output or tx_file
    _save_tx_file(tx, out_path)
    _info(f"Saved to {out_path}")


@tx.command(name="broadcast")
@click.argument("tx_file", type=click.Path(exists=True))
@click.pass_context
def tx_broadcast(ctx: click.Context, tx_file: str) -> None:
    """Broadcast a signed transaction from file to the network."""
    bcs_ctx: BCSContext = ctx.obj
    tx = _load_tx_file(tx_file)

    node = bcs_ctx.node_client()
    try:
        result = node.submit_transaction(tx)
        if result.get("accepted", False):
            _success(f"Broadcast accepted! Tx hash: {tx.hash()}")
        else:
            _error(f"Broadcast rejected: {result.get('reason', 'unknown')}")
    except Exception as exc:
        _error(f"Broadcast failed: {exc}")


# --------------------------------------------------------------------------- #
# offline group
# --------------------------------------------------------------------------- #

@cli.group()
def offline() -> None:
    """Offline mode: enable, create transactions without network, sync later."""
    pass


@offline.command(name="enable")
@click.pass_context
def offline_enable(ctx: click.Context) -> None:
    """Enable offline mode. Transactions will be queued locally."""
    bcs_ctx: BCSContext = ctx.obj
    mgr = bcs_ctx.offline_mgr()
    mgr.enable()
    _success("Offline mode enabled.")
    _info("New transactions will be stored locally and synced when you reconnect.")


@offline.command(name="disable")
@click.pass_context
def offline_disable(ctx: click.Context) -> None:
    """Disable offline mode (does not sync — use 'offline sync')."""
    bcs_ctx: BCSContext = ctx.obj
    mgr = bcs_ctx.offline_mgr()
    mgr.disable()
    _success("Offline mode disabled.")


@offline.command(name="status")
@click.pass_context
def offline_status(ctx: click.Context) -> None:
    """Show offline mode status and pending queue."""
    bcs_ctx: BCSContext = ctx.obj
    mgr = bcs_ctx.offline_mgr()
    status_text = "ENABLED" if mgr.is_offline() else "DISABLED"
    _info(f"Offline mode: {status_text}")
    summary = mgr.get_queue_summary()
    if summary:
        _info("Queue summary:")
        for status_name, count in summary.items():
            _print(f"  {status_name}: {count}")
    else:
        _info("Queue is empty.")


@offline.command(name="prepare-utxos")
@click.option("--address", required=True, help="Address to prepare UTXOs for.")
@click.option("--max-utxos", default=100, help="Maximum UTXOs to cache.")
@click.pass_context
def offline_prepare_utxos(
    ctx: click.Context, address: str, max_utxos: int
) -> None:
    """Download and cache UTXO proof package for offline use."""
    bcs_ctx: BCSContext = ctx.obj
    tracker = bcs_ctx.tracker()
    mgr = bcs_ctx.offline_mgr()

    # Refresh from node first
    node = bcs_ctx.node_client()
    tracker.update_from_node(node, address=address)

    utxos = tracker.get_utxos(address)
    pkg = mgr.prepare_utxo_package(address, utxos, max_utxos=max_utxos)
    _success(f"Prepared UTXO package for {address}")
    _info(f"  UTXOs cached: {pkg['count']}")
    _info(f"  Total amount: {pkg['total_amount']:,} nanoN")


@offline.command(name="create-tx")
@click.option("--spec-file", type=click.Path(exists=True), required=True, help="JSON file with tx specification.")
@click.option("--password", default="", help="Wallet password.")
@click.option("--output", "-o", type=click.Path(), help="Output file for signed tx.")
@click.pass_context
def offline_create_tx(
    ctx: click.Context,
    spec_file: str,
    password: str,
    output: Optional[str],
) -> None:
    """Create a signed transaction while offline using cached UTXOs."""
    bcs_ctx: BCSContext = ctx.obj
    pwd = _get_password(ctx, password)
    w = bcs_ctx.wallet()
    mgr = bcs_ctx.offline_mgr()

    with open(spec_file, "r", encoding="utf-8") as f:
        spec = json.load(f)

    tx = mgr.create_offline_transaction(spec, wallet=w, password=pwd)
    mgr.queue_for_sync(tx)
    _success(f"Offline tx created and queued: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")


@offline.command(name="sync")
@click.pass_context
def offline_sync(ctx: click.Context) -> None:
    """Synchronize queued offline transactions with the network."""
    bcs_ctx: BCSContext = ctx.obj
    mgr = bcs_ctx.offline_mgr()
    node = bcs_ctx.node_client()

    if mgr.is_offline():
        _warning("Offline mode is still enabled. Disabling first...")
        mgr.disable()

    result = mgr.sync_when_online(node)
    _info(f"Sync status: {result.status.value}")
    if result.accepted:
        _success(f"Accepted: {len(result.accepted)} tx(s)")
    if result.rejected:
        _error(f"Rejected: {len(result.rejected)} tx(s)")
        for r in result.rejected:
            _error(f"  {r['tx_hash'][:16]}... — {r['reason']}")
    if result.conflicts:
        _warning(f"Conflicts: {len(result.conflicts)} tx(s)")
    _info(result.message)


# --------------------------------------------------------------------------- #
# identity group
# --------------------------------------------------------------------------- #

@cli.group()
def identity() -> None:
    """Identity operations: DID registration, status queries."""
    pass


@identity.command(name="register")
@click.option("--did", required=True, help="DID to register (e.g. did:bcs:...).")
@click.option("--vc-file", type=click.Path(exists=True), required=True, help="Path to Verifiable Credential JSON file.")
@click.option("--password", default="", help="Wallet password for signing.")
@click.option("--output", "-o", type=click.Path(), help="Save registration tx to file.")
@click.pass_context
def identity_register(
    ctx: click.Context,
    did: str,
    vc_file: str,
    password: str,
    output: Optional[str],
) -> None:
    """Register a DID identity on-chain with a Verifiable Credential."""
    bcs_ctx: BCSContext = ctx.obj
    _info(f"Preparing identity registration for {did}")
    _info(f"Loading VC from {vc_file}")

    with open(vc_file, "r", encoding="utf-8") as f:
        vc_data = json.load(f)

    # Build a REGISTER_IDENTITY transaction (stub — full implementation
    # would integrate with identity.did.DIDManager and core.transaction)
    from core.transaction import Transaction, TxType
    tx = Transaction(
        version=1,
        tx_type=TxType.REGISTER_IDENTITY,
        inputs=[],
        outputs=[],
        extra=json.dumps({"did": did, "vc": vc_data}, sort_keys=True).encode("utf-8"),
    )

    _success(f"Identity registration tx prepared: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")
    else:
        _warning("Transaction not signed or broadcast. Use --output to save, then broadcast.")


@identity.command(name="status")
@click.argument("did", required=False)
@click.pass_context
def identity_status(ctx: click.Context, did: Optional[str]) -> None:
    """Query identity authentication status for a DID or wallet address."""
    bcs_ctx: BCSContext = ctx.obj

    if not did:
        # Use first wallet address and derive DID
        w = bcs_ctx.wallet()
        addrs = w.list_addresses()
        if not addrs:
            _error("No wallet address found. Create a wallet or provide a DID.")
            raise click.Abort()
        # Derive did:bcs from address
        did = f"did:bcs:{addrs[0]}"

    _info(f"Querying identity status for {did}")
    # Stub: in production, query the identity registry / node
    from core.state import IdentityStatus
    _info(f"Status: {IdentityStatus.UNAUTHENTICATED.name}")
    _info("(Full status query requires a connected node with identity service)")


# --------------------------------------------------------------------------- #
# node group
# --------------------------------------------------------------------------- #

@cli.group()
def node() -> None:
    """Node operations: start local node, query status."""
    pass


@node.command(name="start")
@click.option("--config", "node_config", type=click.Path(exists=True), help="Path to node TOML config.")
@click.option("--background", is_flag=True, help="Run in background.")
@click.pass_context
def node_start(ctx: click.Context, node_config: Optional[str], background: bool) -> None:
    """Start a local BCS node."""
    bcs_ctx: BCSContext = ctx.obj
    cfg_path = node_config or "config/node.default.toml"
    _info(f"Starting BCS node with config: {cfg_path}")
    if background:
        _info("Running in background mode (daemon).")
    _warning("Node start is a stub — integrate with your node binary or Docker.")


@node.command(name="status")
@click.pass_context
def node_status(ctx: click.Context) -> None:
    """Query local or remote node status."""
    bcs_ctx: BCSContext = ctx.obj
    node_client = bcs_ctx.node_client()
    _info("Node status query:")
    # Stub output
    _info(f"  RPC endpoint: {bcs_ctx.config.get('node_rpc')}")
    _info(f"  gRPC endpoint: {bcs_ctx.config.get('node_grpc')}")
    _info("  (Full status requires connected node)")


# --------------------------------------------------------------------------- #
# gov group
# --------------------------------------------------------------------------- #

@cli.group()
def gov() -> None:
    """Governance queries: parameters, proposals, voting."""
    pass


@gov.command(name="params")
@click.pass_context
def gov_params(ctx: click.Context) -> None:
    """Query current system governance parameters (phi, psi, validators)."""
    bcs_ctx: BCSContext = ctx.obj
    from currency.params import SystemParameters
    params = SystemParameters()

    if HAS_RICH:
        table = Table(title="BCS System Parameters", box=box.ROUNDED)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("φ (phi)", f"{params.phi_numerator}/{params.phi_denominator} ({params.phi_numerator/params.phi_denominator:.2%})")
        table.add_row("ψ (psi)", f"{params.psi_numerator}/{params.psi_denominator} ({params.psi_numerator/params.psi_denominator:.2%})")
        table.add_row("Block interval", f"{params.block_interval_ms} ms")
        table.add_row("Max block size", f"{params.max_block_size:,} bytes")
        table.add_row("Max tx/block", str(params.max_tx_per_block))
        table.add_row("Min mint", f"{params.min_n_mint:,} nanoN")
        table.add_row("Replenish threshold", f"{params.replenish_threshold:,} nanoN")
        table.add_row("Required gov signatures", str(params.required_gov_signatures))
        _console.print(table)
    else:
        click.echo("BCS System Parameters:")
        click.echo(f"  φ (phi)                 : {params.phi_numerator}/{params.phi_denominator}")
        click.echo(f"  ψ (psi)                 : {params.psi_numerator}/{params.psi_denominator}")
        click.echo(f"  Block interval          : {params.block_interval_ms} ms")
        click.echo(f"  Max block size          : {params.max_block_size:,} bytes")
        click.echo(f"  Max tx/block            : {params.max_tx_per_block}")
        click.echo(f"  Min mint                : {params.min_n_mint:,} nanoN")
        click.echo(f"  Replenish threshold     : {params.replenish_threshold:,} nanoN")
        click.echo(f"  Required gov signatures : {params.required_gov_signatures}")


@gov.command(name="proposals")
@click.pass_context
def gov_proposals(ctx: click.Context) -> None:
    """List active governance proposals."""
    _info("Active governance proposals: (stub — no proposals in local mode)")


# --------------------------------------------------------------------------- #
# export / import helpers at top level
# --------------------------------------------------------------------------- #

@cli.group()
def export() -> None:
    """Export transactions to portable formats (QR, NFC, JSON)."""
    pass


@export.command(name="qr")
@click.argument("tx_file", type=click.Path(exists=True))
@click.pass_context
def export_qr(ctx: click.Context, tx_file: str) -> None:
    """Export a transaction to QR-code data."""
    from exporter import TxExporter
    exporter = TxExporter()
    tx = _load_tx_file(tx_file)
    qr_data = exporter.export_to_qr(tx)
    _success("QR Code Data:")
    click.echo(qr_data)


@export.command(name="nfc")
@click.argument("tx_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Save NFC payload to binary file.")
@click.pass_context
def export_nfc(ctx: click.Context, tx_file: str, output: Optional[str]) -> None:
    """Export a transaction to NFC binary payload."""
    from exporter import TxExporter
    exporter = TxExporter()
    tx = _load_tx_file(tx_file)
    nfc_bytes = exporter.export_to_nfc(tx)
    _success(f"NFC payload ({len(nfc_bytes)} bytes):")
    click.echo(nfc_bytes.hex())
    if output:
        with open(output, "wb") as f:
            f.write(nfc_bytes)
        _info(f"Saved to {output}")


@cli.group()
def import_cmd() -> None:
    """Import transactions from portable formats (QR, NFC, JSON)."""
    pass


@import_cmd.command(name="qr")
@click.argument("qr_data")
@click.option("--output", "-o", type=click.Path(), help="Save imported tx to file.")
@click.pass_context
def import_qr(ctx: click.Context, qr_data: str, output: Optional[str]) -> None:
    """Import a transaction from QR-code data."""
    from exporter import TxExporter
    exporter = TxExporter()
    tx = exporter.import_from_qr(qr_data)
    _success(f"Imported tx: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")


@import_cmd.command(name="nfc")
@click.argument("nfc_hex")
@click.option("--output", "-o", type=click.Path(), help="Save imported tx to file.")
@click.pass_context
def import_nfc(ctx: click.Context, nfc_hex: str, output: Optional[str]) -> None:
    """Import a transaction from NFC hex payload."""
    from exporter import TxExporter
    exporter = TxExporter()
    tx = exporter.import_from_nfc(bytes.fromhex(nfc_hex))
    _success(f"Imported tx: {tx.hash()}")
    if output:
        _save_tx_file(tx, output)
        _info(f"Saved to {output}")


# --------------------------------------------------------------------------- #
# Self-test (CLI dry-run)
# --------------------------------------------------------------------------- #

def _self_test() -> None:
    import tempfile
    from click.testing import CliRunner

    print("=" * 60)
    print("BCS CLI Self-Test")
    print("=" * 60)

    runner = CliRunner()
    tmpdir = tempfile.mkdtemp(prefix="bcs_cli_test_")
    config_path = os.path.join(tmpdir, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({
            "wallet_db": os.path.join(tmpdir, "wallet.db"),
            "balance_cache": os.path.join(tmpdir, "balance.db"),
            "offline_db": os.path.join(tmpdir, "offline.db"),
        }, f)

    # 1. Help
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "BCS Command-Line Interface" in result.output
    print("[1] CLI --help OK")

    # 2. Wallet help
    result = runner.invoke(cli, ["wallet", "--help"])
    assert result.exit_code == 0
    print("[2] wallet --help OK")

    # 3. Wallet create (with config)
    result = runner.invoke(cli, [
        "--config", config_path,
        "wallet", "create",
        "--label", "test-cli",
        "--password", "testpassword123",
    ])
    assert result.exit_code == 0, result.output
    assert "Created new wallet address" in result.output
    print("[3] wallet create OK")

    # 4. Wallet list
    result = runner.invoke(cli, [
        "--config", config_path,
        "wallet", "list",
    ])
    assert result.exit_code == 0
    print("[4] wallet list OK")

    # 5. Wallet balance
    result = runner.invoke(cli, [
        "--config", config_path,
        "wallet", "balance",
    ])
    assert result.exit_code == 0
    print("[5] wallet balance OK")

    # 6. Gov params
    result = runner.invoke(cli, ["gov", "params"])
    assert result.exit_code == 0
    assert "phi" in result.output.lower() or "phi" in result.output
    print("[6] gov params OK")

    # 7. Offline enable
    result = runner.invoke(cli, [
        "--config", config_path,
        "offline", "enable",
    ])
    assert result.exit_code == 0
    print("[7] offline enable OK")

    # 8. Offline status
    result = runner.invoke(cli, [
        "--config", config_path,
        "offline", "status",
    ])
    assert result.exit_code == 0
    print("[8] offline status OK")

    # 9. Export QR (need a tx file first)
    from core.transaction import Transaction, TxInput, TxOutput, TxType
    tx = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=1_000_000_000)],
    )
    tx_file = os.path.join(tmpdir, "tx.json")
    from exporter import TxExporter
    TxExporter().export_to_file([tx], tx_file)

    result = runner.invoke(cli, ["export", "qr", tx_file])
    assert result.exit_code == 0
    print("[9] export qr OK")

    # 10. Import QR
    lines = [line for line in result.output.splitlines() if line and not line.startswith("[")]
    qr_line = lines[1] if len(lines) > 1 else lines[0]  # skip "QR Code Data:" header
    result = runner.invoke(cli, ["import", "qr", qr_line])
    assert result.exit_code == 0
    print("[10] import qr OK")

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir)

    print("\n" + "=" * 60)
    print("All CLI self-tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    # Allow running self-test directly, otherwise invoke CLI
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        _self_test()
    else:
        cli()
