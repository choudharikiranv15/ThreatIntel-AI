"""Hard spending cap: disables billing on the gateway project when a budget is reached.

Google Cloud budgets only alert. This function receives the budget's Pub/Sub
notifications and, once actual spend reaches the budget amount, unlinks the
project from its billing account. Every paid service in the project, the VM
included, then stops. Relink billing in the console to resume.

Notifications arrive several times a day and cost data lags by hours, so
spend can exceed the cap slightly before this runs.

A message with "dryRun": true is evaluated and logged but never acted on, so
the trigger can be tested without shutting anything down. Real budget
notifications never contain that field.
"""

import base64
import json
import os

import functions_framework
import google.auth
from google.auth.transport.requests import AuthorizedSession

PROJECT_ID = os.environ["TARGET_PROJECT_ID"]
BILLING_URL = f"https://cloudbilling.googleapis.com/v1/projects/{PROJECT_ID}/billingInfo"


@functions_framework.cloud_event
def stop_billing(event):
    message = event.data["message"]
    data = json.loads(base64.b64decode(message["data"]).decode("utf-8"))

    cost = float(data.get("costAmount", 0))
    budget = float(data.get("budgetAmount", 0))
    dry_run = data.get("dryRun") is True

    print(json.dumps({
        "budget": data.get("budgetDisplayName"),
        "cost": cost,
        "budgetAmount": budget,
        "currency": data.get("currencyCode"),
        "dryRun": dry_run,
    }))

    if budget <= 0 or cost < budget:
        print(f"Under budget ({cost} of {budget}); no action.")
        return

    if dry_run:
        print(f"DRY RUN: spend {cost} reached budget {budget}; would disable billing for {PROJECT_ID}.")
        return

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = AuthorizedSession(credentials)

    # Informational only: a failed read must never stop the cap from acting.
    try:
        current = session.get(BILLING_URL, timeout=30)
        if current.ok and not current.json().get("billingEnabled"):
            print(f"Billing is already disabled for {PROJECT_ID}.")
            return
    except Exception as error:  # noqa: BLE001
        print(f"Could not read billing state ({error}); disabling anyway.")

    response = session.put(BILLING_URL, json={"billingAccountName": ""}, timeout=30)
    response.raise_for_status()

    print(f"Billing disabled for {PROJECT_ID}: spend {cost} reached budget {budget}.")
