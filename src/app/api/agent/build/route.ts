import { NextResponse } from 'next/server'
import path from 'path'
import fs from 'fs'

export async function POST(req: Request) {
  try {
    const { searchParams } = new URL(req.url)
    const unit = searchParams.get('unit') || 'UN-01'

    // Retorna o binário compilado do agente C# localizado em src/installer/VextHubAgent.exe
    const exePath = path.join(process.cwd(), 'src', 'installer', 'VextHubAgent.exe')
    const fallbackExePath = path.join(process.cwd(), 'src', 'installer', 'VextHub_Agent.exe')

    if (fs.existsSync(exePath)) {
      const fileBuffer = fs.readFileSync(exePath)
      return new NextResponse(fileBuffer, {
        headers: {
          'Content-Type': 'application/x-msdownload',
          'Content-Disposition': `attachment; filename="VextHubAgent_${unit}.exe"`,
        },
      })
    } else if (fs.existsSync(fallbackExePath)) {
      const fileBuffer = fs.readFileSync(fallbackExePath)
      return new NextResponse(fileBuffer, {
        headers: {
          'Content-Type': 'application/x-msdownload',
          'Content-Disposition': `attachment; filename="VextHubAgent_${unit}.exe"`,
        },
      })
    } else {
      return NextResponse.json({ error: 'Binário do agente não encontrado.' }, { status: 404 })
    }
  } catch (error) {
    console.error('Erro na geração do agente:', error)
    return NextResponse.json({ error: 'Falha interna do servidor.' }, { status: 500 })
  }
}
