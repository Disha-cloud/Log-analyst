
import streamlit as st
import ollama

st.set_page_config(page_title="Log Analyst", page_icon="🔍")

st.title("Log Analyst")
st.write("Enter a log entry to get an AI explanation.")

log_entry = st.text_area(
    "Log entry",
    placeholder="Example: Failed login attempt for user admin"
)

if st.button("Analyze Log"):
    if not log_entry.strip():
        st.warning("Please enter a log entry.")
    else:
        with st.spinner("Analyzing log..."):
            response = ollama.chat(
                model="qwen2.5:3b",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security log analyst. "
                            "Explain the log, identify potential risks, "
                            "and distinguish evidence from speculation. "
                            "Do not claim that a single log entry proves "
                            "an attack."
                        )
                    },
                    {
                        "role": "user",
                        "content": log_entry
                    }
                ]
            )

        st.subheader("Analysis")
        st.write(response["message"]["content"])
