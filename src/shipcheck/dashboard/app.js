"use strict";
const $ = (id) => document.getElementById(id);
function clean(value) { return String(value ?? ""); }
function entryCard(item) {
  const receipt = item.receipt || {};
  const payload = item.payload || {};
  const article = document.createElement("article");
  article.className = "entry";
  const title = document.createElement("h3");
  title.textContent = `#${clean(receipt.sequence)} · ${clean(receipt.entry_type)}`;
  const outcome = document.createElement("span");
  outcome.className = `pill ${clean(payload.outcome).toLowerCase()}`;
  outcome.textContent = payload.outcome ? `${clean(payload.assurance_profile)}/${clean(payload.outcome)} · production=${clean(payload.production_ready)}` : clean(payload.state || "recorded");
  const meta = document.createElement("p");
  meta.textContent = `${clean(receipt.created_at)} · ${clean(receipt.entry_hash).slice(0, 16)}…`;
  article.append(title, outcome, meta);
  return article;
}
async function load() {
  $("error").textContent = "";
  const headers = {Authorization: `Bearer ${$("token").value}`};
  try {
    const [verifyResponse, entriesResponse] = await Promise.all([fetch("/api/ledger/verify", {headers}), fetch("/api/entries?limit=100", {headers})]);
    if (!verifyResponse.ok || !entriesResponse.ok) throw new Error("Authorization failed or ledger unavailable");
    const verify = await verifyResponse.json();
    const body = await entriesResponse.json();
    $("integrity").textContent = verify.ok ? "verified" : "failed";
    $("integrity").className = verify.ok ? "good" : "bad";
    $("count").textContent = clean(verify.entries);
    $("tail").textContent = `${clean(verify.tail_hash).slice(0, 12)}…`;
    $("entries").replaceChildren(...(body.entries || []).map(entryCard));
  } catch (error) { $("error").textContent = clean(error.message); }
}
$("load").addEventListener("click", load);
