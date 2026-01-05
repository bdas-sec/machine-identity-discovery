# Speaker Notes - NDC Security Oslo 2026

## Key Messages to Reinforce

### Core Theme
**Non-Human Identities are the new attack surface, and most organizations are blind to them.**

### Three Things to Hammer Home
1. **NHIs outnumber humans 45:1** - and growing with AI agents
2. **NHIs don't have MFA** - one leaked key = full access
3. **Detection is possible** - but you need the right rules

---

## Opening (First 30 Seconds)

**Energy**: High, engaging
**Tone**: Slightly provocative

> "Show of hands - who here has given an API key admin access to something? Keep your hands up if you're sure you've rotated it. Now keep them up if you know exactly what that key can do today."

[Pause for effect]

> "Most hands went down. That's the NHI problem."

---

## Part 1 Talking Points

### Capital One Slide
- **Don't** just read the breach details
- **Do** emphasize: $80M fine, 100M records, ONE SSRF vulnerability
- **Connect**: "This could be your company tomorrow"

### NHI Definition Slide
- **List them**: API keys, service accounts, CI tokens, K8s SAs, AI agents
- **Key point**: "These are identities that authenticate without humans"
- **Surprise fact**: "There are 45x more of these than humans in your org"

### Why They're Targeted
- No MFA - mention this explicitly
- Over-privileged - "Who audits service account permissions?"
- Long-lived - "When did you last rotate that production API key?"
- Invisible - "Not in your HR system, not in your identity provider"

---

## Part 2 Talking Points

### IMDS Explanation
**Use an analogy**:
> "IMDS is like leaving your house keys under the doormat. Works great until someone looks."

**Explain the attack simply**:
1. Attacker finds SSRF in your app
2. Points it at 169.254.169.254
3. Gets your IAM credentials
4. Uses them from anywhere

### AI Agent Risk
**Make it relatable**:
> "You gave your AI agent a tool to make HTTP requests. It can help users! But can it also fetch 169.254.169.254?"

**Warning without fear-mongering**:
> "I'm not saying don't use AI agents. I'm saying understand what they can do."

---

## Part 3 Talking Points (Demo)

### Before Demo
- **Set expectations**: "This is a contained testbed with fake credentials"
- **Explain what they'll see**: "We'll attack, then see the alert in Wazuh"

### During Demo
- **Narrate everything**: Don't type silently
- **Pause at key moments**: Let the output sink in
- **Point out**: "See the AccessKeyId? That's all an attacker needs"

### If Alert Doesn't Appear Immediately
> "These things don't always trigger instantly - let me check... there it is."

### After Demo
- **Connect to real world**: "In production, this alert goes to your SOC"
- **Mention tuning**: "You'd tune this based on your environment"

---

## Part 4 Talking Points

### Immediate Actions
**Be prescriptive**:
> "Here's your homework: Tomorrow, run `truffleHog` against your main repo. You'll find something. I guarantee it."

### Long-term Strategy
**Don't just list tools**:
- Secrets management: "If you're still using .env files, stop today"
- Least privilege: "Every NHI should have exactly what it needs, nothing more"
- OIDC: "Keyless is the future - GitHub Actions, AWS, they all support it"

### AI Agent Guardrails
**Be specific**:
> "URL allowlisting. Input validation. Output filtering. If your AI agent can make HTTP requests, it needs all three."

---

## Part 5 Talking Points

### Key Takeaways
**Repeat each one slowly**:
1. "NHIs are your biggest blind spot"
2. "Assume breach - detect early"
3. "Least privilege is non-negotiable"
4. "AI agents need guardrails"

### Call to Action
**Make it actionable**:
> "This week, do ONE thing: Audit your NHIs. Just count them. I bet you'll be shocked."

---

## Handling Q&A

### Expected Questions

**Q: "How do I find all our NHIs?"**
> "Start with your cloud provider's IAM console. Then check CI/CD secrets. Then grep your code for patterns like 'API_KEY'. It's a journey."

**Q: "Isn't IMDSv2 enough?"**
> "It's a great start. But IMDSv2 just requires a token - if your SSRF can make a PUT request first, you're still vulnerable. Defense in depth."

**Q: "What about AI agents - should we not use them?"**
> "Use them, but with guardrails. Think of it like giving a contractor access to your building - you don't give them master keys on day one."

**Q: "How do we prioritize which NHIs to audit first?"**
> "Start with production access. What can access your databases, your cloud accounts, your customer data? That's your priority list."

### If You Don't Know the Answer
> "That's a great question - I don't have a specific answer, but I'd love to chat after the talk. Find me in the hallway."

---

## Energy Management

- **Part 1**: High energy, wake up the room
- **Part 2**: Technical but engaging, use stories
- **Part 3 (Demo)**: Focused, methodical, let the tech speak
- **Part 4**: Practical, helpful, "here's what you do"
- **Part 5**: Inspiring, call to action

---

## Things to Avoid

- Don't say "obviously" or "simply" - not obvious to everyone
- Don't rush the demo - slow is smooth, smooth is fast
- Don't apologize if something breaks - have backup, stay confident
- Don't deep-dive into Wazuh internals - it's a tool demo, not a Wazuh talk
- Don't fear-monger about AI - be balanced

---

## Backup Phrases

If demo breaks:
> "Let me show you what would have happened..." [switch to video]

If running out of time:
> "I have slides covering this in detail - let me skip to the key takeaway..."

If question is off-topic:
> "That's a great topic but a bit outside our scope today - happy to chat after"

---

## Final Checklist

Before taking the stage:
- [ ] Testbed running and verified
- [ ] Backup video accessible
- [ ] Water on stage
- [ ] Clicker working
- [ ] Timer visible
- [ ] Deep breath
- [ ] You've got this
