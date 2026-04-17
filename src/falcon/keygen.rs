//! Falcon key generation pipeline.

use crate::math::fft::{
    fft, ifft, poly_add, poly_add_muladj_fft, poly_adj_fft, poly_div_autoadj_fft,
    poly_invnorm2_fft, poly_mul_autoadj_fft, poly_mul_fft, poly_sub,
};
use crate::math::fpr::ref_f64::{fpr_of, fpr_rint, fpr_scaled, Fpr};
use crate::math::modp::{
    modp_add, modp_montymul, modp_ninv31, modp_norm, modp_r2, modp_rx, modp_set, modp_sub,
};
use crate::math::ntt::{modp_intt2, modp_mkgm2, modp_ntt2, QB};
use crate::math::primes::primes2;
use crate::math::zint::{
    bitlength, zint_add_scaled_mul_small, zint_bezout, zint_get_top, zint_mod_small_signed,
    zint_mul_small, zint_one_to_plain, zint_rebuild_crt, zint_signed_bit_length, zint_sub_scaled,
};

pub(crate) const MAX_BL_SMALL2: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 212];
pub(crate) const MAX_BL_LARGE2: [usize; 10] = [2, 2, 5, 7, 12, 22, 42, 80, 157, 310];
pub(crate) const DEPTH_INT_FG: u32 = 4;

fn poly_max_bitlength(f: &[u32], flen: usize, fstride: usize, logn: u32) -> u32 {
    let n = 1usize << logn;
    let mut maxbl = 0u32;
    for u in 0..n {
        let bl = zint_signed_bit_length(&f[u * fstride..u * fstride + flen]);
        maxbl = maxbl.max(bl);
    }
    maxbl
}

fn poly_big_to_fp(
    d: &mut [Fpr],
    f: &[u32],
    flen: usize,
    fstride: usize,
    logn: u32,
    maxbl: u32,
    scale: u32,
) {
    let n = 1usize << logn;
    let off = maxbl.saturating_sub(63);
    for u in 0..n {
        d[u] = fpr_scaled(
            zint_get_top(&f[u * fstride..u * fstride + flen], off),
            off as i32 - scale as i32,
        );
    }
}

fn poly_big_to_small(d: &mut [i16], s: &[u32], logn: u32) -> bool {
    let n = 1usize << logn;
    for u in 0..n {
        let z = zint_one_to_plain(&s[u..u + 1]);
        if !(-2047..=2047).contains(&z) {
            return false;
        }
        d[u] = z as i16;
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled(
    f_big: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f_small: &[u32],
    flen_small: usize,
    fstride_small: usize,
    k: &[i32],
    sc: u32,
    logn: u32,
) {
    let n = 1usize << logn;
    let sch = sc / 31;
    let scl = sc % 31;
    for (u, &ku) in k.iter().enumerate().take(n) {
        let mut kf = -ku;
        let mut x = u * fstride_big;
        let mut y = 0usize;
        for v in 0..n {
            zint_add_scaled_mul_small(
                &mut f_big[x..x + flen_big],
                &f_small[y..y + flen_small],
                flen_small,
                kf,
                sch,
                scl,
            );
            if u + v == n - 1 {
                x = 0;
                kf = -kf;
            } else {
                x += fstride_big;
            }
            y += fstride_small;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled_ntt(
    f_big: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f_small: &[u32],
    flen_small: usize,
    fstride_small: usize,
    k: &[i32],
    sc: u32,
    logn: u32,
) {
    let n = 1usize << logn;
    let tlen = flen_small + 1;
    let mut fk = vec![0u32; n * tlen];
    let primes = primes2();

    for (u, prime) in primes.iter().take(tlen).enumerate() {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(flen_small as u32, p, p0i, r2);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        let mut t1 = k.iter().map(|&kw| modp_set(kw, p)).collect::<Vec<_>>();
        modp_ntt2(&mut t1, &gm, logn, p, p0i);

        let mut col = vec![0u32; n];
        for v in 0..n {
            col[v] = zint_mod_small_signed(
                &f_small[v * fstride_small..v * fstride_small + flen_small],
                p,
                p0i,
                r2,
                rx,
            );
        }
        modp_ntt2(&mut col, &gm, logn, p, p0i);
        for v in 0..n {
            col[v] = modp_montymul(modp_montymul(t1[v], col[v], p, p0i), r2, p, p0i);
        }
        modp_intt2(&mut col, &igm, logn, p, p0i);
        insert_column(&mut fk, tlen, u, &col);
    }

    zint_rebuild_crt(&mut fk, tlen, tlen, n, true);
    let sch = sc / 31;
    let scl = sc % 31;
    for u in 0..n {
        zint_sub_scaled(
            &mut f_big[u * fstride_big..u * fstride_big + flen_big],
            &fk[u * tlen..u * tlen + tlen],
            tlen,
            sch,
            scl,
        );
    }
}

fn extract_column(data: &[u32], stride: usize, col: usize, n: usize) -> Vec<u32> {
    let mut out = vec![0u32; n];
    for u in 0..n {
        out[u] = data[u * stride + col];
    }
    out
}

fn insert_column(data: &mut [u32], stride: usize, col: usize, values: &[u32]) {
    for (u, &value) in values.iter().enumerate() {
        data[u * stride + col] = value;
    }
}

fn make_fg_step(data: &[u32], logn: u32, depth: u32, in_ntt: bool, out_ntt: bool) -> Vec<u32> {
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL2[depth as usize];
    let tlen = MAX_BL_SMALL2[depth as usize + 1];
    let primes = primes2();

    let fs = &data[..n * slen];
    let gs = &data[n * slen..2 * n * slen];
    let mut fd = vec![0u32; hn * tlen];
    let mut gd = vec![0u32; hn * tlen];
    let mut fs_norm = vec![0u32; n * slen];
    let mut gs_norm = vec![0u32; n * slen];

    for (u, prime) in primes.iter().take(slen).enumerate() {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        let fx_in = extract_column(fs, slen, u, n);
        let gx_in = extract_column(gs, slen, u, n);
        let mut fx_ntt = fx_in.clone();
        let mut gx_ntt = gx_in.clone();
        if !in_ntt {
            modp_ntt2(&mut fx_ntt, &gm, logn, p, p0i);
            modp_ntt2(&mut gx_ntt, &gm, logn, p, p0i);
        }

        let fx_norm = if in_ntt {
            let mut tmp = fx_in;
            modp_intt2(&mut tmp, &igm, logn, p, p0i);
            tmp
        } else {
            fx_in
        };
        let gx_norm = if in_ntt {
            let mut tmp = gx_in;
            modp_intt2(&mut tmp, &igm, logn, p, p0i);
            tmp
        } else {
            gx_in
        };
        insert_column(&mut fs_norm, slen, u, &fx_norm);
        insert_column(&mut gs_norm, slen, u, &gx_norm);

        let mut fd_col = vec![0u32; hn];
        let mut gd_col = vec![0u32; hn];
        for v in 0..hn {
            let i0 = v << 1;
            let i1 = i0 + 1;
            let w0 = fx_ntt[i0];
            let w1 = fx_ntt[i1];
            fd_col[v] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            let z0 = gx_ntt[i0];
            let z1 = gx_ntt[i1];
            gd_col[v] = modp_montymul(modp_montymul(z0, z1, p, p0i), r2, p, p0i);
        }
        if !out_ntt {
            modp_intt2(&mut fd_col, &igm, logn - 1, p, p0i);
            modp_intt2(&mut gd_col, &igm, logn - 1, p, p0i);
        }
        insert_column(&mut fd, tlen, u, &fd_col);
        insert_column(&mut gd, tlen, u, &gd_col);
    }

    zint_rebuild_crt(&mut fs_norm, slen, slen, n, true);
    zint_rebuild_crt(&mut gs_norm, slen, slen, n, true);

    for (u, prime) in primes.iter().enumerate().take(tlen).skip(slen) {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(slen as u32, p, p0i, r2);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);

        let mut fx = vec![0u32; n];
        let mut gx = vec![0u32; n];
        for v in 0..n {
            fx[v] = zint_mod_small_signed(&fs_norm[v * slen..v * slen + slen], p, p0i, r2, rx);
            gx[v] = zint_mod_small_signed(&gs_norm[v * slen..v * slen + slen], p, p0i, r2, rx);
        }
        modp_ntt2(&mut fx, &gm, logn, p, p0i);
        modp_ntt2(&mut gx, &gm, logn, p, p0i);

        let mut fd_col = vec![0u32; hn];
        let mut gd_col = vec![0u32; hn];
        for v in 0..hn {
            let i0 = v << 1;
            let i1 = i0 + 1;
            let w0 = fx[i0];
            let w1 = fx[i1];
            fd_col[v] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
            let z0 = gx[i0];
            let z1 = gx[i1];
            gd_col[v] = modp_montymul(modp_montymul(z0, z1, p, p0i), r2, p, p0i);
        }
        if !out_ntt {
            modp_intt2(&mut fd_col, &igm, logn - 1, p, p0i);
            modp_intt2(&mut gd_col, &igm, logn - 1, p, p0i);
        }
        insert_column(&mut fd, tlen, u, &fd_col);
        insert_column(&mut gd, tlen, u, &gd_col);
    }

    let mut out = fd;
    out.extend_from_slice(&gd);
    out
}

fn make_fg(f: &[i16], g: &[i16], logn: u32, depth: u32, out_ntt: bool) -> Vec<u32> {
    let n = 1usize << logn;
    let p0 = primes2()[0].p;
    let mut data = vec![0u32; 2 * n];
    for u in 0..n {
        data[u] = modp_set(f[u] as i32, p0);
        data[n + u] = modp_set(g[u] as i32, p0);
    }

    if depth == 0 && out_ntt {
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        let p0i = modp_ninv31(p0);
        modp_mkgm2(&mut gm, &mut igm, logn, primes2()[0].g, p0, p0i);
        modp_ntt2(&mut data[..n], &gm, logn, p0, p0i);
        modp_ntt2(&mut data[n..], &gm, logn, p0, p0i);
        return data;
    }

    for d in 0..depth {
        let in_ntt = d != 0;
        let next_out_ntt = (d + 1) < depth || out_ntt;
        data = make_fg_step(&data, logn - d, d, in_ntt, next_out_ntt);
    }
    data
}

fn modp_poly_rec_res(f: &mut [u32], logn: u32, p: u32, p0i: u32, r2: u32) {
    let hn = 1usize << (logn - 1);
    for u in 0..hn {
        let i0 = u << 1;
        let i1 = i0 + 1;
        let w0 = f[i0];
        let w1 = f[i1];
        f[u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
    }
}

fn solve_ntru_deepest(f: &[i16], g: &[i16], logn: u32) -> Option<(Vec<u32>, Vec<u32>)> {
    let len = MAX_BL_SMALL2[logn as usize];
    let mut fg = make_fg(f, g, logn, logn, false);
    zint_rebuild_crt(&mut fg, len, len, 2, false);

    let fp = fg[..len].to_vec();
    let gp = fg[len..2 * len].to_vec();
    let (mut gp_bezout, mut fp_bezout) = zint_bezout(&fp, &gp)?;
    if zint_mul_small(&mut fp_bezout, QB) != 0 || zint_mul_small(&mut gp_bezout, QB) != 0 {
        return None;
    }
    Some((fp_bezout, gp_bezout))
}

fn solve_ntru_intermediate(
    f: &[i16],
    g: &[i16],
    logn_top: u32,
    depth: u32,
    fd: &[u32],
    gd: &[u32],
) -> Option<(Vec<u32>, Vec<u32>)> {
    let logn = logn_top - depth;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL2[depth as usize];
    let dlen = MAX_BL_SMALL2[depth as usize + 1];
    let llen = MAX_BL_LARGE2[depth as usize];
    let primes = primes2();

    let fg = make_fg(f, g, logn_top, depth, true);
    let ft_ntt = fg[..n * slen].to_vec();
    let gt_ntt = fg[n * slen..2 * n * slen].to_vec();

    let mut ft = vec![0u32; n * slen];
    let mut gt = vec![0u32; n * slen];
    for (u, prime) in primes.iter().take(slen).enumerate() {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);
        let mut fx = extract_column(&ft_ntt, slen, u, n);
        let mut gx = extract_column(&gt_ntt, slen, u, n);
        modp_intt2(&mut fx, &igm, logn, p, p0i);
        modp_intt2(&mut gx, &igm, logn, p, p0i);
        insert_column(&mut ft, slen, u, &fx);
        insert_column(&mut gt, slen, u, &gx);
    }
    zint_rebuild_crt(&mut ft, slen, slen, n, true);
    zint_rebuild_crt(&mut gt, slen, slen, n, true);

    let mut ft_big = vec![0u32; n * llen];
    let mut gt_big = vec![0u32; n * llen];
    for (u, prime) in primes.iter().take(llen).enumerate() {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, prime.g, p, p0i);
        let fx = if u < slen {
            extract_column(&ft_ntt, slen, u, n)
        } else {
            let rx_small = modp_rx(slen as u32, p, p0i, r2);
            let mut col = vec![0u32; n];
            for v in 0..n {
                col[v] =
                    zint_mod_small_signed(&ft[v * slen..v * slen + slen], p, p0i, r2, rx_small);
            }
            modp_ntt2(&mut col, &gm, logn, p, p0i);
            col
        };
        let gx = if u < slen {
            extract_column(&gt_ntt, slen, u, n)
        } else {
            let rx_small = modp_rx(slen as u32, p, p0i, r2);
            let mut col = vec![0u32; n];
            for v in 0..n {
                col[v] =
                    zint_mod_small_signed(&gt[v * slen..v * slen + slen], p, p0i, r2, rx_small);
            }
            modp_ntt2(&mut col, &gm, logn, p, p0i);
            col
        };
        let mut fp = vec![0u32; hn];
        let mut gp = vec![0u32; hn];
        for v in 0..hn {
            fp[v] = zint_mod_small_signed(&fd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
            gp[v] = zint_mod_small_signed(&gd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
        }
        modp_ntt2(&mut fp, &gm, logn - 1, p, p0i);
        modp_ntt2(&mut gp, &gm, logn - 1, p, p0i);

        let mut ft_col = vec![0u32; n];
        let mut gt_col = vec![0u32; n];
        for v in 0..hn {
            let i0 = v << 1;
            let i1 = i0 + 1;
            let ft_a = fx[i0];
            let ft_b = fx[i1];
            let gt_a = gx[i0];
            let gt_b = gx[i1];
            let mfp = modp_montymul(fp[v], r2, p, p0i);
            let mgp = modp_montymul(gp[v], r2, p, p0i);
            ft_col[i0] = modp_montymul(gt_b, mfp, p, p0i);
            ft_col[i1] = modp_montymul(gt_a, mfp, p, p0i);
            gt_col[i0] = modp_montymul(ft_b, mgp, p, p0i);
            gt_col[i1] = modp_montymul(ft_a, mgp, p, p0i);
        }
        modp_intt2(&mut ft_col, &igm, logn, p, p0i);
        modp_intt2(&mut gt_col, &igm, logn, p, p0i);
        insert_column(&mut ft_big, llen, u, &ft_col);
        insert_column(&mut gt_big, llen, u, &gt_col);
    }

    zint_rebuild_crt(&mut ft_big, llen, llen, n, true);
    zint_rebuild_crt(&mut gt_big, llen, llen, n, true);
    let mut adj_f = vec![fpr_of(0); n];
    let mut adj_g = vec![fpr_of(0); n];
    let mut invnorm = vec![fpr_of(0); hn];

    let maxbl_fg =
        poly_max_bitlength(&ft, slen, slen, logn).max(poly_max_bitlength(&gt, slen, slen, logn));
    poly_big_to_fp(&mut adj_f, &ft, slen, slen, logn, maxbl_fg, maxbl_fg);
    poly_big_to_fp(&mut adj_g, &gt, slen, slen, logn, maxbl_fg, maxbl_fg);
    fft(&mut adj_f, logn);
    fft(&mut adj_g, logn);
    poly_invnorm2_fft(&mut invnorm, &adj_f, &adj_g, logn);
    poly_adj_fft(&mut adj_f, logn);
    poly_adj_fft(&mut adj_g, logn);

    let mut prev_maxbl_fg = u32::MAX;
    let mut fg_len = llen;
    let current_maxbl_fg = loop {
        let maxbl_f = poly_max_bitlength(&ft_big, fg_len, llen, logn);
        let maxbl_g = poly_max_bitlength(&gt_big, fg_len, llen, logn);
        let current_maxbl_fg = maxbl_f.max(maxbl_g);
        while fg_len * 31 >= current_maxbl_fg as usize + 43 {
            fg_len -= 1;
        }
        if current_maxbl_fg <= maxbl_fg || current_maxbl_fg >= prev_maxbl_fg {
            break current_maxbl_fg;
        }
        prev_maxbl_fg = current_maxbl_fg;

        let mut scale_fg = current_maxbl_fg.saturating_sub(30);
        let mut rt1 = vec![fpr_of(0); n];
        let mut rt2 = vec![fpr_of(0); n];
        poly_big_to_fp(
            &mut rt1,
            &ft_big,
            fg_len,
            llen,
            logn,
            current_maxbl_fg,
            scale_fg,
        );
        poly_big_to_fp(
            &mut rt2,
            &gt_big,
            fg_len,
            llen,
            logn,
            current_maxbl_fg,
            scale_fg,
        );
        fft(&mut rt1, logn);
        fft(&mut rt2, logn);
        poly_mul_fft(&mut rt1, &adj_f, logn);
        poly_mul_fft(&mut rt2, &adj_g, logn);
        poly_add(&mut rt2, &rt1, logn);
        poly_mul_autoadj_fft(&mut rt2, &invnorm, logn);
        ifft(&mut rt2, logn);

        let mut max_kx = 0u64;
        for &v in &rt2 {
            let kx = fpr_rint(v).unsigned_abs();
            max_kx = max_kx.max(kx);
        }
        if max_kx >= (1u64 << 62) {
            return None;
        }
        let mut scale_k = bitlength((max_kx >> 31) as u32);
        if scale_k + scale_fg < maxbl_fg {
            scale_k = maxbl_fg - scale_fg;
            if scale_k > 62 {
                break current_maxbl_fg;
            }
        }
        scale_fg += scale_k;

        let mut k = vec![0i32; n];
        for u in 0..n {
            let kx = fpr_rint(rt2[u]);
            k[u] = if kx < 0 {
                -(((-kx) >> scale_k) as i32)
            } else {
                (kx >> scale_k) as i32
            };
        }

        if depth <= DEPTH_INT_FG {
            poly_sub_scaled_ntt(
                &mut ft_big,
                fg_len,
                llen,
                &ft,
                slen,
                slen,
                &k,
                scale_fg - maxbl_fg,
                logn,
            );
            poly_sub_scaled_ntt(
                &mut gt_big,
                fg_len,
                llen,
                &gt,
                slen,
                slen,
                &k,
                scale_fg - maxbl_fg,
                logn,
            );
        } else {
            poly_sub_scaled(
                &mut ft_big,
                fg_len,
                llen,
                &ft,
                slen,
                slen,
                &k,
                scale_fg - maxbl_fg,
                logn,
            );
            poly_sub_scaled(
                &mut gt_big,
                fg_len,
                llen,
                &gt,
                slen,
                slen,
                &k,
                scale_fg - maxbl_fg,
                logn,
            );
        }
    };

    if current_maxbl_fg > (slen * 31) as u32 {
        return None;
    }

    let mut out_f = vec![0u32; n * slen];
    let mut out_g = vec![0u32; n * slen];
    for u in 0..n {
        let src_f = &ft_big[u * llen..u * llen + slen];
        let src_g = &gt_big[u * llen..u * llen + slen];
        out_f[u * slen..u * slen + slen].copy_from_slice(src_f);
        out_g[u * slen..u * slen + slen].copy_from_slice(src_g);
    }
    Some((out_f, out_g))
}

fn solve_ntru_binary_depth1(
    f: &[i16],
    g: &[i16],
    logn_top: u32,
    fd: &[u32],
    gd: &[u32],
) -> Option<(Vec<u32>, Vec<u32>)> {
    let logn = logn_top - 1;
    let n_top = 1usize << logn_top;
    let n = 1usize << logn;
    let hn = n >> 1;
    let slen = MAX_BL_SMALL2[1];
    let dlen = MAX_BL_SMALL2[2];
    let llen = MAX_BL_LARGE2[1];
    let primes = primes2();

    let mut ft = vec![0u32; n * slen];
    let mut gt = vec![0u32; n * slen];
    let mut ft_big = vec![0u32; n * llen];
    let mut gt_big = vec![0u32; n * llen];

    for (u, prime) in primes.iter().take(llen).enumerate() {
        let p = prime.p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(dlen as u32, p, p0i, r2);

        let mut ft_top = vec![0u32; n_top];
        let mut gt_top = vec![0u32; n_top];
        for v in 0..n_top {
            ft_top[v] = modp_set(f[v] as i32, p);
            gt_top[v] = modp_set(g[v] as i32, p);
        }
        let mut gm_top = vec![0u32; n_top];
        let mut igm_top = vec![0u32; n_top];
        modp_mkgm2(&mut gm_top, &mut igm_top, logn_top, prime.g, p, p0i);
        modp_ntt2(&mut ft_top, &gm_top, logn_top, p, p0i);
        modp_ntt2(&mut gt_top, &gm_top, logn_top, p, p0i);
        for e in ((logn + 1)..=logn_top).rev() {
            modp_poly_rec_res(&mut ft_top, e, p, p0i, r2);
            modp_poly_rec_res(&mut gt_top, e, p, p0i, r2);
        }
        let mut fx = ft_top[..n].to_vec();
        let mut gx = gt_top[..n].to_vec();
        let igm = igm_top[..n].to_vec();
        let mut fp = vec![0u32; hn];
        let mut gp = vec![0u32; hn];
        for v in 0..hn {
            fp[v] = zint_mod_small_signed(&fd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
            gp[v] = zint_mod_small_signed(&gd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
        }
        modp_ntt2(&mut fp, &gm_top, logn - 1, p, p0i);
        modp_ntt2(&mut gp, &gm_top, logn - 1, p, p0i);

        let mut ft_col = vec![0u32; n];
        let mut gt_col = vec![0u32; n];
        for v in 0..hn {
            let i0 = v << 1;
            let i1 = i0 + 1;
            let ft_a = fx[i0];
            let ft_b = fx[i1];
            let gt_a = gx[i0];
            let gt_b = gx[i1];
            let mfp = modp_montymul(fp[v], r2, p, p0i);
            let mgp = modp_montymul(gp[v], r2, p, p0i);
            ft_col[i0] = modp_montymul(gt_b, mfp, p, p0i);
            ft_col[i1] = modp_montymul(gt_a, mfp, p, p0i);
            gt_col[i0] = modp_montymul(ft_b, mgp, p, p0i);
            gt_col[i1] = modp_montymul(ft_a, mgp, p, p0i);
        }
        modp_intt2(&mut ft_col, &igm, logn, p, p0i);
        modp_intt2(&mut gt_col, &igm, logn, p, p0i);
        insert_column(&mut ft_big, llen, u, &ft_col);
        insert_column(&mut gt_big, llen, u, &gt_col);

        if u < slen {
            modp_intt2(&mut fx, &igm, logn, p, p0i);
            modp_intt2(&mut gx, &igm, logn, p, p0i);
            insert_column(&mut ft, slen, u, &fx);
            insert_column(&mut gt, slen, u, &gx);
        }
    }

    let mut both_big = ft_big.clone();
    both_big.extend_from_slice(&gt_big);
    zint_rebuild_crt(&mut both_big, llen, llen, n << 1, true);
    let (ft_big, gt_big) = both_big.split_at(n * llen);
    let ft_big = ft_big.to_vec();
    let gt_big = gt_big.to_vec();

    let mut both_small = ft.clone();
    both_small.extend_from_slice(&gt);
    zint_rebuild_crt(&mut both_small, slen, slen, n << 1, true);
    let (ft_small, gt_small) = both_small.split_at(n * slen);
    let ft_small = ft_small.to_vec();
    let gt_small = gt_small.to_vec();

    let maxbl_fg = poly_max_bitlength(&ft_small, slen, slen, logn)
        .max(poly_max_bitlength(&gt_small, slen, slen, logn));
    let maxbl_fg_big = poly_max_bitlength(&ft_big, llen, llen, logn)
        .max(poly_max_bitlength(&gt_big, llen, llen, logn));
    if maxbl_fg > 53 || maxbl_fg_big > 53 {
        return None;
    }

    let mut rt_f = vec![fpr_of(0); n];
    let mut rt_g = vec![fpr_of(0); n];
    let mut rt_base_f = vec![fpr_of(0); n];
    let mut rt_base_g = vec![fpr_of(0); n];
    poly_big_to_fp(&mut rt_f, &ft_big, llen, llen, logn, maxbl_fg_big, 0);
    poly_big_to_fp(&mut rt_g, &gt_big, llen, llen, logn, maxbl_fg_big, 0);
    poly_big_to_fp(&mut rt_base_f, &ft_small, slen, slen, logn, maxbl_fg, 0);
    poly_big_to_fp(&mut rt_base_g, &gt_small, slen, slen, logn, maxbl_fg, 0);

    fft(&mut rt_f, logn);
    fft(&mut rt_g, logn);
    fft(&mut rt_base_f, logn);
    fft(&mut rt_base_g, logn);
    let mut rt_num = vec![fpr_of(0); n];
    poly_add_muladj_fft(&mut rt_num, &rt_f, &rt_g, &rt_base_f, &rt_base_g, logn);
    let mut rt_den = vec![fpr_of(0); hn];
    poly_invnorm2_fft(&mut rt_den, &rt_base_f, &rt_base_g, logn);
    poly_mul_autoadj_fft(&mut rt_num, &rt_den, logn);
    ifft(&mut rt_num, logn);
    for v in &mut rt_num {
        *v = fpr_of(fpr_rint(*v));
    }
    fft(&mut rt_num, logn);
    let mut kf = rt_base_f.clone();
    let mut kg = rt_base_g.clone();
    poly_mul_fft(&mut kf, &rt_num, logn);
    poly_mul_fft(&mut kg, &rt_num, logn);
    poly_sub(&mut rt_f, &kf, logn);
    poly_sub(&mut rt_g, &kg, logn);
    ifft(&mut rt_f, logn);
    ifft(&mut rt_g, logn);

    let mut out_f = vec![0u32; n];
    let mut out_g = vec![0u32; n];
    for u in 0..n {
        out_f[u] = fpr_rint(rt_f[u]) as u32;
        out_g[u] = fpr_rint(rt_g[u]) as u32;
    }
    Some((out_f, out_g))
}

fn solve_ntru_binary_depth0(
    f: &[i16],
    g: &[i16],
    logn: u32,
    fp_prev: &[u32],
    gp_prev: &[u32],
) -> Option<(Vec<u32>, Vec<u32>)> {
    let n = 1usize << logn;
    let hn = n >> 1;
    let p = primes2()[0].p;
    let p0i = modp_ninv31(p);
    let r2 = modp_r2(p, p0i);
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    modp_mkgm2(&mut gm, &mut igm, logn, primes2()[0].g, p, p0i);

    let mut fp = vec![0u32; hn];
    let mut gp = vec![0u32; hn];
    for u in 0..hn {
        fp[u] = modp_set(zint_one_to_plain(&fp_prev[u..u + 1]), p);
        gp[u] = modp_set(zint_one_to_plain(&gp_prev[u..u + 1]), p);
    }
    modp_ntt2(&mut fp, &gm, logn - 1, p, p0i);
    modp_ntt2(&mut gp, &gm, logn - 1, p, p0i);

    let mut ft = vec![0u32; n];
    let mut gt = vec![0u32; n];
    for u in 0..n {
        ft[u] = modp_set(f[u] as i32, p);
        gt[u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2(&mut ft, &gm, logn, p, p0i);
    modp_ntt2(&mut gt, &gm, logn, p, p0i);
    for u in (0..n).step_by(2) {
        let ft_a = ft[u];
        let ft_b = ft[u + 1];
        let gt_a = gt[u];
        let gt_b = gt[u + 1];
        let mfp = modp_montymul(fp[u >> 1], r2, p, p0i);
        let mgp = modp_montymul(gp[u >> 1], r2, p, p0i);
        ft[u] = modp_montymul(gt_b, mfp, p, p0i);
        ft[u + 1] = modp_montymul(gt_a, mfp, p, p0i);
        gt[u] = modp_montymul(ft_b, mgp, p, p0i);
        gt[u + 1] = modp_montymul(ft_a, mgp, p, p0i);
    }
    modp_intt2(&mut ft, &igm, logn, p, p0i);
    modp_intt2(&mut gt, &igm, logn, p, p0i);

    let mut f_ntt = ft.clone();
    let mut g_ntt = gt.clone();
    modp_ntt2(&mut f_ntt, &gm, logn, p, p0i);
    modp_ntt2(&mut g_ntt, &gm, logn, p, p0i);
    let mut f_poly = vec![0u32; n];
    let mut adj_f = vec![0u32; n];
    let mut g_poly = vec![0u32; n];
    let mut adj_g = vec![0u32; n];
    f_poly[0] = modp_set(f[0] as i32, p);
    adj_f[0] = modp_set(f[0] as i32, p);
    g_poly[0] = modp_set(g[0] as i32, p);
    adj_g[0] = modp_set(g[0] as i32, p);
    for u in 1..n {
        f_poly[u] = modp_set(f[u] as i32, p);
        adj_f[n - u] = modp_set(-(f[u] as i32), p);
        g_poly[u] = modp_set(g[u] as i32, p);
        adj_g[n - u] = modp_set(-(g[u] as i32), p);
    }
    modp_ntt2(&mut f_poly, &gm, logn, p, p0i);
    modp_ntt2(&mut adj_f, &gm, logn, p, p0i);
    modp_ntt2(&mut g_poly, &gm, logn, p, p0i);
    modp_ntt2(&mut adj_g, &gm, logn, p, p0i);

    let mut num = vec![0u32; n];
    let mut den = vec![0u32; n];
    for u in 0..n {
        let w = modp_montymul(adj_f[u], r2, p, p0i);
        num[u] = modp_montymul(w, f_ntt[u], p, p0i);
        den[u] = modp_montymul(w, f_poly[u], p, p0i);
    }
    for u in 0..n {
        let w = modp_montymul(adj_g[u], r2, p, p0i);
        num[u] = modp_add(num[u], modp_montymul(w, g_ntt[u], p, p0i), p);
        den[u] = modp_add(den[u], modp_montymul(w, g_poly[u], p, p0i), p);
    }

    let mut gm2 = vec![0u32; n];
    let mut igm2 = vec![0u32; n];
    modp_mkgm2(&mut gm2, &mut igm2, logn, primes2()[0].g, p, p0i);
    modp_intt2(&mut num, &igm2, logn, p, p0i);
    modp_intt2(&mut den, &igm2, logn, p, p0i);
    let mut rt_den_full = vec![fpr_of(0); n];
    for u in 0..n {
        rt_den_full[u] = fpr_of(modp_norm(den[u], p) as i64);
    }
    fft(&mut rt_den_full, logn);
    let rt_den = rt_den_full[..hn].to_vec();
    let mut rt_num = vec![fpr_of(0); n];
    for u in 0..n {
        rt_num[u] = fpr_of(modp_norm(num[u], p) as i64);
    }
    fft(&mut rt_num, logn);
    poly_div_autoadj_fft(&mut rt_num, &rt_den, logn);
    ifft(&mut rt_num, logn);

    let mut k = vec![0u32; n];
    for u in 0..n {
        k[u] = modp_set(fpr_rint(rt_num[u]) as i32, p);
    }
    let mut k_ntt = k.clone();
    let mut f_small = vec![0u32; n];
    let mut g_small = vec![0u32; n];
    for u in 0..n {
        f_small[u] = modp_set(f[u] as i32, p);
        g_small[u] = modp_set(g[u] as i32, p);
    }
    modp_ntt2(&mut k_ntt, &gm, logn, p, p0i);
    modp_ntt2(&mut f_small, &gm, logn, p, p0i);
    modp_ntt2(&mut g_small, &gm, logn, p, p0i);
    for u in 0..n {
        let kw = modp_montymul(k_ntt[u], r2, p, p0i);
        f_ntt[u] = modp_sub(f_ntt[u], modp_montymul(kw, f_small[u], p, p0i), p);
        g_ntt[u] = modp_sub(g_ntt[u], modp_montymul(kw, g_small[u], p, p0i), p);
    }
    modp_intt2(&mut f_ntt, &igm, logn, p, p0i);
    modp_intt2(&mut g_ntt, &igm, logn, p, p0i);

    let mut out_f = vec![0u32; n];
    let mut out_g = vec![0u32; n];
    for u in 0..n {
        out_f[u] = modp_norm(f_ntt[u], p) as u32;
        out_g[u] = modp_norm(g_ntt[u], p) as u32;
    }
    Some((out_f, out_g))
}

pub(crate) fn solve_ntru(f: &[i16], g: &[i16], logn: u32) -> Option<(Vec<i16>, Vec<i16>)> {
    let n = 1usize << logn;
    let (mut fd, mut gd) = solve_ntru_deepest(f, g, logn)?;

    if logn <= 2 {
        for depth in (0..logn).rev() {
            let (new_f, new_g) = solve_ntru_intermediate(f, g, logn, depth, &fd, &gd)?;
            fd = new_f;
            gd = new_g;
        }
    } else {
        for depth in (2..logn).rev() {
            let (new_f, new_g) = solve_ntru_intermediate(f, g, logn, depth, &fd, &gd)?;
            fd = new_f;
            gd = new_g;
        }
        let (new_f, new_g) = solve_ntru_binary_depth1(f, g, logn, &fd, &gd)?;
        fd = new_f;
        gd = new_g;
        let (new_f, new_g) = solve_ntru_binary_depth0(f, g, logn, &fd, &gd)?;
        fd = new_f;
        gd = new_g;
    }

    let mut big_f = vec![0i16; n];
    let mut big_g = vec![0i16; n];
    if !poly_big_to_small(&mut big_f, &fd, logn) || !poly_big_to_small(&mut big_g, &gd, logn) {
        return None;
    }

    let p = primes2()[0].p;
    let p0i = modp_ninv31(p);
    let mut gm = vec![0u32; n];
    let mut igm = vec![0u32; n];
    modp_mkgm2(&mut gm, &mut igm, logn, primes2()[0].g, p, p0i);
    let mut ft = vec![0u32; n];
    let mut gt = vec![0u32; n];
    let mut big_ft = vec![0u32; n];
    let mut big_gt = vec![0u32; n];
    for u in 0..n {
        ft[u] = modp_set(f[u] as i32, p);
        gt[u] = modp_set(g[u] as i32, p);
        big_ft[u] = modp_set(big_f[u] as i32, p);
        big_gt[u] = modp_set(big_g[u] as i32, p);
    }
    modp_ntt2(&mut ft, &gm, logn, p, p0i);
    modp_ntt2(&mut gt, &gm, logn, p, p0i);
    modp_ntt2(&mut big_ft, &gm, logn, p, p0i);
    modp_ntt2(&mut big_gt, &gm, logn, p, p0i);
    let r = modp_montymul(QB, 1, p, p0i);
    for u in 0..n {
        let z = modp_sub(
            modp_montymul(ft[u], big_gt[u], p, p0i),
            modp_montymul(gt[u], big_ft[u], p, p0i),
            p,
        );
        if z != r {
            return None;
        }
    }

    Some((big_f, big_g))
}

#[cfg(test)]
mod tests {
    use super::solve_ntru;
    use crate::math::ntt::QB;

    fn negacyclic_mul(a: &[i16], b: &[i16]) -> Vec<i64> {
        let n = a.len();
        let mut out = vec![0i64; n];
        for (i, &ai) in a.iter().enumerate() {
            for (j, &bj) in b.iter().enumerate() {
                let prod = ai as i64 * bj as i64;
                let k = i + j;
                if k < n {
                    out[k] += prod;
                } else {
                    out[k - n] -= prod;
                }
            }
        }
        out
    }

    #[test]
    fn solve_ntru_matches_reference_vector_from_c() {
        let f = [
            10, 11, -11, 24, -19, -4, -21, 27, -26, 6, -17, -1, 39, 5, 18, -12,
        ];
        let g = [
            24, 25, -4, -15, 6, 14, 28, -3, 20, 27, 53, 17, 1, -41, -38, 31,
        ];
        let expected_f = [
            -14, 51, -31, -61, 13, 26, 55, 43, -24, -8, -1, 33, 3, 34, -24, 51,
        ];
        let expected_g = [
            55, 20, -25, 61, 52, -1, -42, -1, 49, -14, 36, -27, 10, 5, 3, -64,
        ];

        let (big_f, big_g) = solve_ntru(&f, &g, 4).expect("reference vector must solve");
        assert_eq!(big_f, expected_f);
        assert_eq!(big_g, expected_g);
    }

    #[test]
    fn solve_ntru_satisfies_ntru_equation() {
        let f = [
            10, 11, -11, 24, -19, -4, -21, 27, -26, 6, -17, -1, 39, 5, 18, -12,
        ];
        let g = [
            24, 25, -4, -15, 6, 14, 28, -3, 20, 27, 53, 17, 1, -41, -38, 31,
        ];
        let (big_f, big_g) = solve_ntru(&f, &g, 4).expect("reference vector must solve");

        let fg = negacyclic_mul(&f, &big_g);
        let gf = negacyclic_mul(&g, &big_f);
        for (idx, (&lhs, &rhs)) in fg.iter().zip(gf.iter()).enumerate() {
            let value = lhs - rhs;
            if idx == 0 {
                assert_eq!(value, i64::from(QB));
            } else {
                assert_eq!(value, 0);
            }
        }
    }
}
