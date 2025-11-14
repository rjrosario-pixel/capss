def sample_file_with_progress(input_path, output_path, limit=100000):
    print(f"\n📦 Sampling from {input_path}...")
    count = 0
    progress_interval = limit // 100  # 1% increments

    with open(input_path, "r", encoding="utf-8", errors="ignore") as infile, \
         open(output_path, "w", encoding="utf-8") as outfile:

        for line in infile:
            if count >= limit:
                break
            line = line.strip()
            if line:
                outfile.write(line + "\n")
                count += 1
                if count % progress_interval == 0:
                    percent = (count * 100) // limit
                    print(f"⏳ {percent}% done", end="\r")

    print(f"✅ {output_path} created with {count} URLs.")

# Run both samplings
sample_file_with_progress("github_phishing.txt", "phishing_sample.txt", 100000)
sample_file_with_progress("safe_links.txt", "safe_sample.txt", 100000)

print("\n🎉 Done: Both files created with 100,000 lines each.")
