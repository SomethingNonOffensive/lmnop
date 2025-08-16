- 👋 Hi, I’m @SomethingNonOffensive
- 👀 I’m interested in ... keeping this name. i worked real hard on it.  
- 🌱 I’m currently learning ... words really do hurt and my parents are liars.
- 💞️ I’m looking to collaborate on ... the commode... of ethics?
- 📫 How to reach me ... bu hand.

<!---
SomethingNonOffensive/SomethingNonOffensive is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->

## LMNOP Setup

This repository includes a sample Flask app `app.py`.
To run it, install dependencies and set environment variables:

```
pip install -r requirements.txt
export SECRET_KEY="change_me"
export ADMIN_PASSWORD="change_me"
python app.py
```

`SECRET_KEY` is required so session and CSRF tokens remain valid between restarts.

### Sample data

The first time the app runs it seeds a few test accounts and jobs so you can explore:

- `manager` / `manager` — manager role
- `alice` / `alice` — worker role
- `bob` / `bob` — worker role

Two example clients and jobs are also created.
