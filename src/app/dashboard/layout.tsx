import React from 'react'
import { redirect } from 'next/navigation'
import { Sidebar } from '@/components/dashboard/Sidebar'
import { BottomNav } from '@/components/dashboard/BottomNav'
import { UpdateBanner } from '@/components/dashboard/UpdateBanner'
import { createClient } from '@/utils/supabase/server'
import { isLocalAuthFallbackAllowed } from '@/utils/security/api-auth'

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const supabase = await createClient()

  if (!isLocalAuthFallbackAllowed()) {
    const userResult = await supabase?.auth?.getUser?.()
    const user = userResult?.data?.user

    if (!user) {
      redirect('/login')
    }
  }

  return (
    <div className="flex flex-col lg:flex-row h-screen bg-background overflow-hidden">
      <Sidebar />
      <BottomNav />

      <main className="flex-1 relative overflow-y-auto focus:outline-none scroll-smooth pb-32 lg:pb-0 lg:ml-80">
        <div className="py-6 px-4 lg:py-10 lg:px-12 max-w-[1600px] mx-auto transition-all duration-500">
          <UpdateBanner />
          {children}
        </div>
      </main>
    </div>
  )
}
