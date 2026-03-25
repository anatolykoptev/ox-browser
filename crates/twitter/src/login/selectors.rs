//! CSS selectors and JS evaluate snippets for Twitter login page.
//! Isolated here so DOM changes require editing only this file.

// --- CSS selectors (used with page.find_element) ---

pub const USERNAME_INPUT: &str = "input[autocomplete='username']";
pub const PASSWORD_INPUT: &str = "input[name='password']";
pub const LOGIN_BUTTON: &str = "button[data-testid='LoginForm_Login_Button']";
pub const OCF_TEXT_INPUT: &str = "input[data-testid='ocfEnterTextTextInput']";
pub const HOME_INDICATOR: &str = "a[data-testid='AppTabBar_Home_Link']";
pub const ERROR_MESSAGE: &str = "div[data-testid='error-detail']";

// --- JS evaluate snippets (for elements not findable by CSS alone) ---

/// Find "Next" button by text content. Returns the element or null.
pub const JS_FIND_NEXT_BUTTON: &str = r#"
    (() => {
        const btns = document.querySelectorAll('button[role="button"]');
        for (const b of btns) {
            if (b.textContent.trim() === 'Next') return b;
        }
        return null;
    })()
"#;

/// Read the heading text near the OCF input to disambiguate TOTP vs username confirm.
pub const JS_READ_HEADING: &str = r#"
    (() => {
        const el = document.querySelector('h1, h2, [role="heading"]');
        return el ? el.textContent.trim() : '';
    })()
"#;

/// Check if current URL contains /home (login success indicator).
pub const JS_CHECK_HOME_URL: &str = "window.location.href.includes('/home')";
