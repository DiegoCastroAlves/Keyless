//! What secrets look like: the public formats of the tokens and keys that
//! services issue (most start with a prefix the service documents, so they
//! can be found, and revoked when leaked), and variables whose name says they
//! hold a secret. Only the shape is checked: nothing is ever sent anywhere to
//! see whether a secret still works.

use std::sync::OnceLock;

use regex::Regex;

/// A kind of secret.
pub struct Pattern {
    pub id: &'static str,
    /// The service's name, as people know it ("" for kinds of any service).
    pub service: &'static str,
    /// "token", "key", "secret", "webhook", "webhook_secret", or a kind of
    /// any service: "private_key", "database_password", "url_password",
    /// "jwt".
    pub kind: &'static str,
    regex: Regex,
}

/// The formats: id, service, what the service calls it ("token", "key"…;
/// the UI words it in the user's language), and the shape. The secret is
/// the whole match, or its first group when there is one.
const FORMATS: &[(&str, &str, &str, &str)] = &[
    ("private_key", "", "private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("github_pat", "GitHub", "token", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("github_token", "GitHub", "token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    ("gitlab_token", "GitLab", "token", r"\bgl(?:pat|dt|ft|rt|cbt|ptt|soat|imt)-[A-Za-z0-9_-]{20,}\b"),
    ("bitbucket_token", "Bitbucket", "token", r"\bATBB[A-Za-z0-9_=.-]{32,}\b"),
    ("atlassian_token", "Atlassian", "token", r"\bATATT3[A-Za-z0-9_=-]{180,}"),
    ("slack_token", "Slack", "token", r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}"),
    ("slack_app_token", "Slack", "token", r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+\b"),
    ("slack_webhook", "Slack", "webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}"),
    ("discord_webhook", "Discord", "webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}"),
    ("discord_bot", "Discord", "token", r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b"),
    ("telegram_bot", "Telegram", "token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    ("stripe_live", "Stripe", "key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
    ("stripe_test", "Stripe (test)", "key", r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b"),
    ("stripe_webhook", "Stripe", "webhook_secret", r"\bwhsec_[A-Za-z0-9+/=]{32,}"),
    ("square_token", "Square", "token", r"\b(?:EAAA[A-Za-z0-9_-]{60}|sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})\b"),
    ("braintree_token", "Braintree", "token", r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"),
    ("shopify_token", "Shopify", "token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    ("aws_access_key", "AWS", "key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    ("azure_storage", "Azure Storage", "key", r"AccountKey=([A-Za-z0-9+/]{86}==)"),
    ("google_api_key", "Google", "key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("google_oauth", "Google OAuth", "secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
    ("digitalocean_token", "DigitalOcean", "token", r"\bdo[opr]_v1_[a-f0-9]{64}\b"),
    ("heroku_token", "Heroku", "token", r"\bHRKU-[A-Za-z0-9_-]{60,}"),
    ("fly_token", "Fly.io", "token", r"\b(?:fo1_[A-Za-z0-9_-]{43}|fm2_[A-Za-z0-9+/=_-]{100,})"),
    ("render_token", "Render", "key", r"\brnd_[A-Za-z0-9]{32}\b"),
    ("netlify_token", "Netlify", "token", r"\bnfp_[A-Za-z0-9]{36}\b"),
    ("supabase_token", "Supabase", "token", r"\bsbp_[a-f0-9]{40}\b"),
    ("supabase_secret", "Supabase", "key", r"\bsb_secret_[A-Za-z0-9_-]{20,}"),
    ("planetscale_token", "PlanetScale", "token", r"\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,64}\b"),
    ("databricks_token", "Databricks", "token", r"\bdapi[a-f0-9]{32}(?:-\d)?\b"),
    ("pulumi_token", "Pulumi", "token", r"\bpul-[a-f0-9]{40}\b"),
    ("terraform_token", "Terraform Cloud", "token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,}"),
    ("vault_token", "HashiCorp Vault", "token", r"\bhv[sbr]\.[A-Za-z0-9_-]{24,}"),
    ("doppler_token", "Doppler", "token", r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"),
    ("age_key", "age", "key", r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"),
    ("openai_key", "OpenAI", "key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("anthropic_key", "Anthropic", "key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
    ("huggingface_token", "Hugging Face", "token", r"\bhf_[A-Za-z0-9]{34,}\b"),
    ("replicate_token", "Replicate", "token", r"\br8_[A-Za-z0-9]{37}\b"),
    ("groq_key", "Groq", "key", r"\bgsk_[A-Za-z0-9]{52}\b"),
    ("perplexity_key", "Perplexity", "key", r"\bpplx-[A-Za-z0-9]{48}\b"),
    ("xai_key", "xAI", "key", r"\bxai-[A-Za-z0-9]{80}\b"),
    ("twilio_key", "Twilio", "key", r"\bSK[0-9a-f]{32}\b"),
    ("sendgrid_key", "SendGrid", "key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("mailgun_key", "Mailgun", "key", r"\bkey-[0-9a-f]{32}\b"),
    ("mailchimp_key", "Mailchimp", "key", r"\b[0-9a-f]{32}-us\d{1,2}\b"),
    ("resend_key", "Resend", "key", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b"),
    ("npm_token", "npm", "token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("pypi_token", "PyPI", "token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    ("rubygems_key", "RubyGems", "key", r"\brubygems_[a-f0-9]{48}\b"),
    ("nuget_key", "NuGet", "key", r"\boy2[a-z0-9]{43}\b"),
    ("docker_token", "Docker Hub", "token", r"\bdckr_pat_[A-Za-z0-9_-]{27}\b"),
    ("jfrog_token", "JFrog", "token", r"\b(?:AKCp[A-Za-z0-9]{69}|cmVmdGtu[A-Za-z0-9]{56})\b"),
    ("linear_key", "Linear", "key", r"\blin_api_[A-Za-z0-9]{40}\b"),
    ("notion_token", "Notion", "token", r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"),
    ("airtable_token", "Airtable", "token", r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"),
    ("asana_token", "Asana", "token", r"\b\d/\d{16}:[a-f0-9]{32}\b"),
    ("figma_token", "Figma", "token", r"\bfigd_[A-Za-z0-9_-]{40,}"),
    ("contentful_token", "Contentful", "token", r"\bCFPAT-[A-Za-z0-9_-]{43}\b"),
    ("dropbox_token", "Dropbox", "token", r"\bsl\.[A-Za-z0-9_-]{130,}"),
    ("postman_key", "Postman", "key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    ("grafana_token", "Grafana", "token", r"\b(?:glc_[A-Za-z0-9+/]{32,}={0,2}|glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})"),
    ("newrelic_key", "New Relic", "key", r"\bNRAK-[A-Z0-9]{27}\b"),
    ("sentry_token", "Sentry", "token", r"\b(?:sntrys_[A-Za-z0-9+/=_-]{60,}|sntryu_[a-f0-9]{64})"),
    ("shippo_token", "Shippo", "token", r"\bshippo_live_[a-f0-9]{40}\b"),
    ("lob_key", "Lob", "key", r"\blive_[a-f0-9]{35}\b"),
    ("mapbox_token", "Mapbox", "token", r"\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"),
    ("clickup_token", "ClickUp", "token", r"\bpk_\d{6,}_[A-Z0-9]{32}\b"),
    ("frameio_token", "Frame.io", "token", r"\bfio-u-[A-Za-z0-9_=-]{64}\b"),
    ("adafruit_key", "Adafruit IO", "key", r"\baio_[A-Za-z0-9]{28}\b"),
    ("prefect_key", "Prefect", "key", r"\bpnu_[A-Za-z0-9]{36}\b"),
    ("readme_key", "ReadMe", "key", r"\brdme_[a-z0-9]{70}\b"),
    ("scalingo_token", "Scalingo", "token", r"\btk-us-[A-Za-z0-9_-]{48}\b"),
    ("typeform_token", "Typeform", "token", r"\btfp_[A-Za-z0-9_.=-]{59}\b"),
    ("jwt", "", "jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("database_url", "", "database_password", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^:@/\s]*:([^@\s]{3,})@"),
    ("url_password", "", "url_password", r"\bhttps?://[^:@/\s]+:([^@\s]{6,})@"),
];

/// Names of variables that hold a secret.
const SECRET_NAME: &str = r"(?i)(secret|token|passw(?:or)?d|\bpwd\b|_pwd\b|pass\b|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|signing[_-]?key|encryption[_-]?key|session[_-]?key|webhook)";

fn formats() -> &'static [Pattern] {
    static FORMATS_COMPILED: OnceLock<Vec<Pattern>> = OnceLock::new();
    FORMATS_COMPILED.get_or_init(|| {
        FORMATS
            .iter()
            .filter_map(|&(id, service, kind, re)| Regex::new(re).ok().map(|regex| Pattern { id, service, kind, regex }))
            .collect()
    })
}

fn secret_name() -> &'static Regex {
    static NAME: OnceLock<Regex> = OnceLock::new();
    NAME.get_or_init(|| Regex::new(SECRET_NAME).expect("valid pattern"))
}

/// How many formats are known.
pub fn count() -> usize {
    FORMATS.len()
}

/// A secret found in some text.
#[derive(Debug, PartialEq)]
pub struct Found<'a> {
    pub id: &'static str,
    pub service: &'static str,
    pub kind: &'static str,
    pub value: &'a str,
}

/// The secrets in `text` whose format is known.
pub fn find(text: &str) -> Vec<Found<'_>> {
    let mut found: Vec<Found> = Vec::new();
    for pattern in formats() {
        for caps in pattern.regex.captures_iter(text) {
            let Some(m) = caps.get(1).or_else(|| caps.get(0)) else { continue };
            // One finding per place: the first, most specific format wins.
            if found.iter().any(|f| overlaps(text, f.value, m.as_str())) {
                continue;
            }
            found.push(Found { id: pattern.id, service: pattern.service, kind: pattern.kind, value: m.as_str() });
        }
    }
    found
}

fn overlaps(text: &str, a: &str, b: &str) -> bool {
    let start = |s: &str| s.as_ptr() as usize - text.as_ptr() as usize;
    let (a0, b0) = (start(a), start(b));
    a0 < b0 + b.len() && b0 < a0 + a.len()
}

/// A variable whose name says it holds a secret, and whose value looks like
/// one rather than an example.
pub fn secret_variable(name: &str, value: &str) -> bool {
    secret_name().is_match(name) && !placeholder(value)
}

/// Values that only stand for a secret: empty, short, examples, references
/// to other variables, booleans and the like.
pub fn placeholder(value: &str) -> bool {
    let v = value.trim();
    let lower = v.to_lowercase();
    if v.chars().count() < 8 || v.contains(char::is_whitespace) {
        return true;
    }
    if (v.starts_with('<') && v.ends_with('>')) || v.starts_with("${") || v.starts_with("$(") || (v.starts_with('%') && v.ends_with('%')) || v.starts_with("{{") {
        return true;
    }
    if v.chars().all(|c| c == v.chars().next().unwrap_or('x')) {
        return true;
    }
    const WORDS: [&str; 16] = [
        "changeme", "change_me", "change-me", "example", "placeholder", "your_", "your-", "yourkey", "yoursecret", "xxxx", "dummy", "sample",
        "replace", "todo", "fixme", "insert",
    ];
    if WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    // Paths, plain addresses and numbers are settings, not secrets.
    lower.starts_with('/') || lower.starts_with("./") || lower.starts_with("~/") || ((lower.starts_with("http://") || lower.starts_with("https://")) && !lower.contains('@')) || v.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Shows enough of a secret to recognize it: its known prefix, or a few
/// characters, then the end.
pub fn masked(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len().max(4));
    }
    let head = chars.iter().position(|c| *c == '_' || *c == '-').filter(|&i| i < 12).map_or(4, |i| i + 1).min(chars.len() / 3);
    let tail = 3;
    format!("{}…{}", chars[..head].iter().collect::<String>(), chars[chars.len() - tail..].iter().collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test tokens are put together at run time, so the source never holds
    /// something that looks like a real secret.
    fn token(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn every_format_compiles() {
        assert_eq!(formats().len(), FORMATS.len());
        assert!(count() >= 75);
    }

    #[test]
    fn finds_known_formats() {
        let cases = [
            ("github_token", token(&["gh", "p_", &"a1B2".repeat(9)])),
            ("gitlab_token", token(&["glp", "at-", &"x".repeat(20)])),
            ("slack_token", token(&["xo", "xb-", "1234-5678-abcdefghij"])),
            ("stripe_live", token(&["sk", "_live_", &"Ab1".repeat(10)])),
            ("aws_access_key", token(&["AK", "IA", "ABCDEFGHIJKLMNOP"])),
            ("google_api_key", token(&["AI", "za", &"B".repeat(35)])),
            ("npm_token", token(&["np", "m_", &"c".repeat(36)])),
            ("openai_key", token(&["sk", "-proj-", &"d".repeat(40)])),
            ("anthropic_key", token(&["sk", "-ant-api03-", &"e".repeat(90)])),
            ("sendgrid_key", token(&["S", "G.", &"f".repeat(22), ".", &"g".repeat(43)])),
            ("supabase_token", token(&["sb", "p_", &"a".repeat(40)])),
            ("private_key", token(&["-----BEGIN ", "OPENSSH PRIVATE KEY-----"])),
        ];
        for (id, value) in &cases {
            let text = format!("KEY={value}");
            let found = find(&text);
            assert_eq!(found.first().map(|f| f.id), Some(*id), "{id}: {found:?}");
        }
    }

    #[test]
    fn database_passwords() {
        let text = token(&["DATABASE_URL=postgres://app:", "s3cretpw", "@db.example.com:5432/app"]);
        let found = find(&text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "database_url");
        assert_eq!(found[0].value, "s3cretpw");
    }

    #[test]
    fn secret_variables_and_placeholders() {
        assert!(secret_variable("JWT_SECRET", "q8Zr2Lm9Vx4Tb7Np"));
        assert!(secret_variable("db_password", "q8Zr2Lm9Vx4Tb7Np"));
        assert!(!secret_variable("JWT_SECRET", "changeme"));
        assert!(!secret_variable("JWT_SECRET", "your_secret_here"));
        assert!(!secret_variable("JWT_SECRET", "${OTHER_SECRET}"));
        assert!(!secret_variable("API_TOKEN", "<token>"));
        assert!(!secret_variable("PORT", "q8Zr2Lm9Vx4Tb7Np"));
        assert!(!secret_variable("TOKEN_URL", "https://auth.example.com/token"));
        assert!(!secret_variable("SECRET_PATH", "/etc/app/secret"));
        assert!(placeholder("12345678"));
    }

    #[test]
    fn masks() {
        assert_eq!(masked(&token(&["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789"])), "ghp_…789");
        assert_eq!(masked("q8Zr2Lm9Vx4Tb7Np"), "q8Zr…7Np");
        assert_eq!(masked("short"), "•••••");
    }
}
