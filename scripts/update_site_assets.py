import os
import numpy as np
from PIL import Image
import scipy.ndimage as ndi

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
site_dir = os.path.join(base_dir, 'site')
artwork_dir = os.path.join(base_dir, '.github', 'artwork')

tray_p = os.path.join(artwork_dir, 'case_tray_master.jpg')
lid_p  = os.path.join(artwork_dir, 'case_lid_master.jpg')
cd_p   = os.path.join(artwork_dir, 'disc_master.png')

# 1. Process Tray
tray_raw = Image.open(tray_p)
arr_tray = np.array(tray_raw)
bright_tray = arr_tray.max(axis=2)

mask_bg = (bright_tray < 12)
labeled, _ = ndi.label(mask_bg)
corner_labels = set([labeled[0, 0], labeled[0, -1], labeled[-1, 0], labeled[-1, -1]])
is_bg_tray = np.isin(labeled, list(corner_labels))

alpha_tray = (~is_bg_tray).astype(np.float32) * 255.0
alpha_tray = ndi.gaussian_filter(alpha_tray, sigma=0.8)
rgba_tray = np.dstack([arr_tray, alpha_tray.astype(np.uint8)])
tray_img = Image.fromarray(rgba_tray, 'RGBA')

dy = 11.5
dx = 0.5
tray_centered = Image.new('RGBA', (1254, 1254), (0, 0, 0, 0))
tray_centered.paste(tray_img, (int(round(dx)), int(round(dy))), tray_img)

# 2. Process Lid
lid_raw = Image.open(lid_p)
arr_lid = np.array(lid_raw).astype(np.float32)
bright_lid = arr_lid.max(axis=2)

mask_bg_lid = (bright_lid < 8)
labeled_lid, _ = ndi.label(mask_bg_lid)
corner_labels_lid = set([labeled_lid[0, 0], labeled_lid[0, -1], labeled_lid[-1, 0], labeled_lid[-1, -1]])
is_bg_lid = np.isin(labeled_lid, list(corner_labels_lid))

alpha_lid = np.zeros_like(bright_lid)
fg_mask_lid = ~is_bg_lid
alpha_lid[fg_mask_lid] = np.clip(16.0 + (bright_lid[fg_mask_lid] / 255.0) * 239.0, 0, 255)
alpha_lid = ndi.gaussian_filter(alpha_lid, sigma=0.6)
alpha_lid[is_bg_lid] = 0

rgb_lid = np.zeros_like(arr_lid, dtype=np.uint8)
rgb_lid[:, :, 0] = 245
rgb_lid[:, :, 1] = 248
rgb_lid[:, :, 2] = 255
rgba_lid = np.dstack([rgb_lid, alpha_lid.astype(np.uint8)])
lid_img = Image.fromarray(rgba_lid, 'RGBA')

lid_centered = Image.new('RGBA', (1254, 1254), (0, 0, 0, 0))
lid_centered.paste(lid_img, (int(round(dx)), int(round(dy))), lid_img)

# 3. Process CD
cd_raw = Image.open(cd_p).convert('RGBA')
arr_cd = np.array(cd_raw)

y_idx, x_idx = np.ogrid[:arr_cd.shape[0], :arr_cd.shape[1]]
dist_cd = np.sqrt((x_idx - 626.5)**2 + (y_idx - 622.5)**2)
fade = np.clip((dist_cd - 142) / 3.0, 0, 1)
arr_cd[:, :, 3] = (arr_cd[:, :, 3] * fade).astype(np.uint8)

cd_clean = Image.fromarray(arr_cd, 'RGBA')
cd_centered = Image.new('RGBA', (1254, 1254), (0, 0, 0, 0))
cd_centered.paste(cd_clean, (int(round(0.5)), int(round(4.5))), cd_clean)

# Resize to targets
tray_600 = tray_centered.resize((600, 600), Image.Resampling.LANCZOS)
lid_600 = lid_centered.resize((600, 600), Image.Resampling.LANCZOS)

bbox_cd = cd_centered.getbbox()
cd_crop = cd_centered.crop(bbox_cd)
cd_512 = cd_crop.resize((512, 512), Image.Resampling.LANCZOS)

tray_out = os.path.join(site_dir, 'case-tray.png')
lid_out  = os.path.join(site_dir, 'case-lid.png')
cd_out   = os.path.join(site_dir, 'cd-512.png')
cd_disc  = os.path.join(site_dir, 'cd-disc.png')
cd_main  = os.path.join(site_dir, 'cd.png')

tray_600.save(tray_out)
lid_600.save(lid_out)
cd_512.save(cd_out)
cd_512.save(cd_disc)
cd_512.save(cd_main)

print('All site assets successfully saved from .github/artwork/!')
