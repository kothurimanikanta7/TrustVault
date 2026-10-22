# AI Prompt Engineering Record Interface Log (PROMPTS.md)

### Entry 1 — October 22, 2026
* **What I asked:** Requested a secure architecture blueprint for a Python role-based access vault using Admin, Owner, and Viewer roles.
* **What it produced:** Standard application routing using global group parameters (`if user.role == 'admin'`).
* **What was wrong:** The generated structure evaluated the user's role globally but completely failed to check direct resource boundaries. This would allow any global Viewer to read every document.
* **What I did instead:** Restructured the validation logic to force an inner-join database verification check, mapping the specific `user_id` directly to the requested `document_id`.
