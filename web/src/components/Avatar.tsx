import { useState } from 'react'

type Props = {
  src?: string
  name?: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

function initial(name?: string) {
  const s = (name || '?').trim()
  return s.slice(0, 1).toUpperCase()
}

export function Avatar({ src, name, size = 'md', className }: Props) {
  const [broken, setBroken] = useState(false)
  const cls = `avatar ${size === 'sm' ? 'sm' : size === 'lg' ? 'lg' : ''} ${className || ''}`.trim()
  if (src && !broken) {
    return <img className={cls} src={src} alt={name || ''} onError={() => setBroken(true)} />
  }
  return (
    <div className={cls} aria-hidden>
      {initial(name)}
    </div>
  )
}
