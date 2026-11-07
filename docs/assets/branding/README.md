# Konstapel artwork

The Konstapel mascot is a bunny wearing a custom cap inspired by the Swedish
båtmössa, with a K badge. The artwork uses navy (`#172D45`), gold (`#D8AB59`), and
warm white (`#FFF9EF`). It follows the repository's [Apache-2.0 license](../../../LICENSE).

- `konstapel-logo-light.svg` and `.png`: colour logo for light backgrounds.
- `konstapel-logo-dark.svg` and `.png`: single-colour logo for dark backgrounds.
- `konstapel-social-preview.svg` and `.png`: repository social card.

The SVGs are editable sources. Their wordmark uses DejaVu Sans Bold; the PNG
exports preserve its appearance without requiring that font on the viewer's
device. Keep each PNG in sync when changing its SVG. The README logos are
1140 × 400 pixels and displayed at a smaller width.

## README images and tags

The root README uses a `picture` element to select the dark-theme logo, with the
colour logo as its fallback. Both image paths are relative to the README.
GitHub resolves them within the branch or tag being viewed, so commit the README
and its artwork together. A future tag retains the artwork from that revision;
existing tags are unchanged. Keep these paths relative rather than pointing to
the latest image on `main`.

## Repository social preview

Upload `konstapel-social-preview.png` through the repository's **Settings →
General → Social preview → Edit → Upload an image**. This setting controls link
previews when the repository is shared; it does not insert an image into the
README and is not versioned with tags. Updating the file in Git alone does not
update the uploaded social preview.

The card is 1280 × 640 pixels, with important content inside an 80-pixel margin
following GitHub's social-preview template. The PNG must stay below 1 MB. See
[GitHub's social-preview guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/customizing-your-repositorys-social-media-preview).
