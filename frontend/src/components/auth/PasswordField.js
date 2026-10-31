"use client";

import { useState } from 'react';
import styles from './auth.module.css';

// A password input with a Show/Hide button, so a confirmation field is not needed.
export default function PasswordField({ id, label, value, onChange, autoComplete, hint, invalid = false, minLength }) {
  const [visible, setVisible] = useState(false);
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>{label}</label>
      <div className={styles.inputWrap}>
        <input
          id={id}
          name={id}
          type={visible ? 'text' : 'password'}
          className={styles.input}
          value={value}
          onChange={event => onChange(event.target.value)}
          autoComplete={autoComplete}
          aria-describedby={hintId}
          aria-invalid={invalid || undefined}
          minLength={minLength}
          maxLength={128}
          required
        />
        <button
          type="button"
          className={styles.reveal}
          onClick={() => setVisible(current => !current)}
          aria-pressed={visible}
          aria-controls={id}
        >
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>
      {hint && <p id={hintId} className={styles.hint}>{hint}</p>}
    </div>
  );
}
