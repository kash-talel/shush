use super::*;
use std::collections::HashMap;

#[derive(Default)]
struct Fake {
    vals: HashMap<(u8, String, String), String>,
    subs: HashMap<(u8, String), Vec<String>>,
    fail_user: bool,
    fail_subs: bool,
}

fn h(x: Hive) -> u8 {
    x as u8
}

impl Fake {
    fn val(&mut self, hive: Hive, key: &str, name: &str, v: &str) {
        self.vals
            .insert((h(hive), key.into(), name.into()), v.into());
    }
    fn user_install(&mut self, dir: &str) {
        self.val(
            Hive::User,
            &format!(r"{UNINSTALL}\shush"),
            "UninstallString",
            &format!(r#""{dir}\uninstall.exe""#),
        );
    }
    fn msi(&mut self, hive: Hive, guid: &str, loc: Option<&str>) {
        let key = format!(r"{UNINSTALL}\{guid}");
        self.subs
            .entry((h(hive), UNINSTALL.into()))
            .or_default()
            .push(guid.into());
        self.val(hive, &key, "DisplayName", "shush");
        self.val(hive, &key, "WindowsInstaller", "1");
        if let Some(l) = loc {
            self.val(hive, &key, "InstallLocation", l);
        }
    }
}

impl Reg for Fake {
    fn value(&self, hive: Hive, key: &str, name: &str) -> Result<Option<String>, String> {
        if self.fail_user && hive == Hive::User {
            return Err("denied".into());
        }
        Ok(self.vals.get(&(h(hive), key.into(), name.into())).cloned())
    }
    fn subkeys(&self, hive: Hive, key: &str) -> Result<Vec<String>, String> {
        if self.fail_subs {
            return Err("denied".into());
        }
        Ok(self
            .subs
            .get(&(h(hive), key.into()))
            .cloned()
            .unwrap_or_default())
    }
}

const DIR: &str = r"C:\Users\a\AppData\Local\shush";

fn run(f: &Fake, dir: &str) -> (InstallKind, Vec<String>) {
    let mut log = Vec::new();
    let k = detect(f, Path::new(dir), "shush", &mut |m| log.push(m));
    (k, log)
}

#[test]
fn per_user_installer_may_self_update() {
    let mut f = Fake::default();
    f.user_install(DIR);
    // Case and a trailing slash do not matter.
    assert_eq!(
        run(&f, r"c:\users\a\appdata\local\SHUSH\").0,
        InstallKind::Installer
    );
    assert!(InstallKind::Installer.can_self_update());
}

#[test]
fn per_machine_msi_is_managed_and_never_updated() {
    let mut f = Fake::default();
    f.msi(Hive::Machine64, "{AAAA}", Some(r"C:\Program Files\shush\"));
    let (k, _) = run(&f, r"C:\Program Files\shush");
    assert_eq!(k, InstallKind::Managed);
    assert!(!k.can_self_update() && !k.may_check());
    // The 32-bit view counts too, and so does an MSI that records no location.
    let mut f = Fake::default();
    f.msi(Hive::Machine32, "{BBBB}", None);
    assert_eq!(run(&f, r"D:\anywhere").0, InstallKind::Managed);
}

#[test]
fn hand_copied_exe_is_notify_only() {
    let mut f = Fake::default();
    f.user_install(DIR);
    f.msi(Hive::Machine64, "{AAAA}", Some(r"C:\Program Files\shush"));
    // Neither registration points at this folder.
    let (k, log) = run(&f, r"D:\tools\shush");
    assert_eq!(k, InstallKind::HandCopied);
    assert!(!k.can_self_update() && k.may_check());
    assert!(log.is_empty());
    assert_eq!(run(&Fake::default(), r"D:\x").0, InstallKind::HandCopied);
}

#[test]
fn unreadable_or_ambiguous_registry_fails_safe_with_a_log_line() {
    let f = Fake {
        fail_user: true,
        ..Fake::default()
    };
    let (k, log) = run(&f, DIR);
    assert_eq!(k, InstallKind::Unknown);
    assert!(!k.can_self_update() && k.may_check());
    assert_eq!(log.len(), 1);

    let f = Fake {
        fail_subs: true,
        ..Fake::default()
    };
    assert_eq!(run(&f, DIR).0, InstallKind::Unknown);

    let mut f = Fake::default();
    f.user_install(DIR);
    f.msi(Hive::Machine64, "{AAAA}", Some(DIR));
    let (k, log) = run(&f, DIR);
    assert_eq!(k, InstallKind::Unknown);
    assert!(log[0].contains("both"));
}

#[test]
fn uninstall_string_forms() {
    assert_eq!(command_dir(r#""C:\a b\uninstall.exe" /S"#), r"C:\a b");
    assert_eq!(command_dir(r"C:\a\uninstall.exe /S"), r"C:\a");
}

#[cfg(windows)]
#[test]
fn real_registry_reads_do_not_fail_on_this_machine() {
    // Smoke test of the Win32 wrapper: absent keys are Ok(None), not errors.
    let r = super::win::WinReg;
    assert_eq!(
        r.value(Hive::User, r"Software\shush-no-such-key", "x"),
        Ok(None)
    );
    assert!(r.subkeys(Hive::Machine64, UNINSTALL).is_ok());
    assert!(r.subkeys(Hive::Machine32, UNINSTALL).is_ok());
}
