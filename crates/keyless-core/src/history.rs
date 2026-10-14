//! An item's earlier versions (the server keeps the ciphertext each write
//! replaced, see the `item_versions` migration): what each one changed, for
//! every app's "item history".

use crate::item::{Field, ItemDetails, ItemOverview};

fn all_fields(details: &ItemDetails) -> impl Iterator<Item = &Field> {
    details.fields.iter().chain(details.sections.iter().flat_map(|s| s.fields.iter()))
}

/// What changed from `old` to `new`, by name: field labels, or ":title",
/// ":websites", ":notes", ":tags".
pub fn changes(old: (&ItemOverview, &ItemDetails), new: (&ItemOverview, &ItemDetails)) -> Vec<String> {
    let mut changed = Vec::new();
    if old.0.title != new.0.title {
        changed.push(":title".to_string());
    }
    if old.0.urls != new.0.urls {
        changed.push(":websites".to_string());
    }
    if old.0.tags != new.0.tags {
        changed.push(":tags".to_string());
    }
    for field in all_fields(old.1) {
        let after = all_fields(new.1).find(|f| f.id == field.id);
        if after.is_none_or(|f| f.value != field.value || f.label != field.label) && !changed.contains(&field.label) {
            changed.push(field.label.clone());
        }
    }
    for field in all_fields(new.1) {
        if !all_fields(old.1).any(|f| f.id == field.id) && !changed.contains(&field.label) {
            changed.push(field.label.clone());
        }
    }
    if old.1.notes != new.1.notes {
        changed.push(":notes".to_string());
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{FieldKind, FieldPurpose};

    fn field(id: &str, label: &str, value: &str) -> Field {
        Field { id: id.into(), label: label.into(), kind: FieldKind::Text, value: value.into(), purpose: Some(FieldPurpose::Username), extra: Default::default() }
    }

    #[test]
    fn names_what_changed() {
        let old_o = ItemOverview { title: "GitHub".into(), ..Default::default() };
        let mut old_d = ItemDetails::default();
        old_d.fields = vec![field("u", "username", "ana"), field("p", "password", "one")];
        let mut new_o = old_o.clone();
        let mut new_d = ItemDetails::default();
        new_d.fields = vec![field("u", "username", "ana"), field("p", "password", "two"), field("x", "pin", "1234")];
        assert_eq!(changes((&old_o, &old_d), (&new_o, &new_d)), vec!["password", "pin"]);
        new_o.title = "GitHub work".into();
        new_d.notes = "hello".into();
        new_d.fields.truncate(1);
        assert_eq!(changes((&old_o, &old_d), (&new_o, &new_d)), vec![":title", "password", ":notes"]);
    }
}
